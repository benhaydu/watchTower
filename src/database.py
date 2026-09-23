import sqlite3

def init_db():
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            raw_line TEXT,
            received_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS parsed_events (
        id INTEGER PRIMARY KEY,
        log_id INTEGER,
        event_type TEXT,
        username TEXT,
        source_ip TEXT,
        port INTEGER,
        target_user TEXT,
        command TEXT,
        FOREIGN KEY(log_id) REFERENCES logs(id)
    )
""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY,
        rule_name TEXT NOT NULL,
        matched_entity TEXT,
        count INTEGER NOT NULL,
        window_seconds INTEGER NOT NULL,
        triggered_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
""")

    conn.commit()
    conn.close()


def is_suppressed(rule_name: str, matched_entity: str, suppression_seconds: int) -> bool:
    """True if this exact (rule_name, matched_entity) already alerted within
    the last suppression_seconds -- i.e. this would be a repeat of an alert
    still considered "active", not a new occurrence.
    `IS ?` (not `= ?`) is required for matched_entity: SQL's `=` never matches
    NULL against NULL, but ungrouped rules (e.g. rate_spike) store NULL there.
    """
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()

    cursor.execute(
        """SELECT 1 FROM alerts
           WHERE rule_name = ?
             AND matched_entity IS ?
             AND triggered_at >= datetime('now', ?)
           LIMIT 1""",
        (rule_name, matched_entity, f"-{suppression_seconds} seconds")
    )
    found = cursor.fetchone() is not None
    conn.close()
    return found


def get_alerts(limit: int = 100):
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()

    cursor.execute(
        """SELECT id, rule_name, matched_entity, count, window_seconds, triggered_at
           FROM alerts
           ORDER BY triggered_at DESC
           LIMIT ?""",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "rule_name": row[1],
            "matched_entity": row[2],
            "count": row[3],
            "window_seconds": row[4],
            "triggered_at": row[5],
        }
        for row in rows
    ]


def insert_alert(rule_name: str, matched_entity: str, count: int, window_seconds: int):
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            """INSERT INTO alerts (rule_name, matched_entity, count, window_seconds)
               VALUES (?,?,?,?)""",
            (rule_name, matched_entity, count, window_seconds)
        )
        conn.commit()
    finally:
        conn.close()

def get_unparsed_logs():
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT logs.id, logs.raw_line
        FROM logs
        LEFT JOIN parsed_events ON logs.id = parsed_events.log_id
        WHERE parsed_events.log_id IS NULL
    """)

    results = cursor.fetchall()
    conn.close()
    return results

def insert_parsed_logs(log_id: int, event_type: str, username: str, source_ip: str, port: int,
                        target_user: str = None, command: str = None):
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            """INSERT INTO parsed_events
               (log_id, event_type, username, source_ip, port, target_user, command)
               VALUES (?,?,?,?,?,?,?)""",
             (log_id, event_type, username, source_ip, port, target_user, command)
        )
        conn.commit()
    finally:
        conn.close()







def insert_logs(source: str, lines: list[str]) -> list[int]:
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()

    log_ids = []
    try:
        for line in lines:
            cursor.execute(
                "INSERT INTO logs (source, raw_line) VALUES (?, ?)",
                (source, line)
            )
            log_ids.append(cursor.lastrowid)
        conn.commit()
    finally:
        conn.close()

    return log_ids


def check_threshold_rule(event_type: str, threshold: int, window_seconds: int, distinct_column: str = None, group_by_ip: bool = True, username: str = None):
    # Windows on logs.received_at (DB insert time), not the timestamp embedded
    # in the raw log line. This is a deliberate choice, not an oversight: for
    # live tailing (the real deployment) insert time and event time are
    # basically identical. It only diverges when logs arrive out of real-time --
    # replaying test_auth.log, or the collector flushing a backlog after
    # downtime -- where every backlogged line gets received_at ~= now,
    # which can produce misleading window counts (a backlog flush can look
    # like a burst; a real slow-burn attack can look compressed). Switching to
    # event-time would mean parsing syslog's timestamp (no year, no timezone)
    # -- not worth it until backfill/replay scenarios actually matter.
    conn = sqlite3.connect("app_database.db")
    cursor = conn.cursor()

    if distinct_column:
        count_expr = f"COUNT(DISTINCT {distinct_column})"
    else:
        count_expr = "COUNT(*)"

    # Optional extra filter on which account was targeted. Unlike
    # distinct_column/group_by_ip (which pick a column or shape the query),
    # `username` is an actual data VALUE -- so it goes through a ? placeholder,
    # never pasted directly into the SQL string.
    username_filter = "AND parsed_events.username = ?" if username else ""

    if group_by_ip:
        query = f"""
            SELECT parsed_events.source_ip, {count_expr} as attempt_count
            FROM parsed_events
            JOIN logs ON parsed_events.log_id = logs.id
            WHERE parsed_events.event_type = ?
              AND logs.received_at >= datetime('now', ?)
              {username_filter}
            GROUP BY parsed_events.source_ip
            HAVING {count_expr} >= ?
        """
    else:
        # No grouping: one overall count across every source_ip, for
        # rules like "rate spike" that care about total volume rather
        # than any single IP's behavior. HAVING still works here without
        # GROUP BY -- SQLite treats the whole result as a single group.
        query = f"""
            SELECT {count_expr} as attempt_count
            FROM parsed_events
            JOIN logs ON parsed_events.log_id = logs.id
            WHERE parsed_events.event_type = ?
              AND logs.received_at >= datetime('now', ?)
              {username_filter}
            HAVING {count_expr} >= ?
        """

    # Build the parameter tuple in the same order the ? placeholders
    # appear in the query text above: event_type, window, [username], threshold.
    params = [event_type, f"-{window_seconds} seconds"]
    if username:
        params.append(username)
    params.append(threshold)

    cursor.execute(query, tuple(params))
    results = cursor.fetchall()
    conn.close()
    return results
