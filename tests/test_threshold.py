import sqlite3

import pytest

from database import init_db, check_threshold_rule


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Fresh empty database in a temp folder (database.py opens
    "app_database.db" by relative path)."""
    monkeypatch.chdir(tmp_path)
    init_db()


def add_event(event_type, ip, username=None, age_seconds=0):
    """Insert one log row + one parsed_events row.

    age_seconds says how long ago the line was 'received'. We let SQLite
    compute the timestamp with datetime('now', ...) so it has exactly the
    same format and clock as the query under test.
    """
    conn = sqlite3.connect("app_database.db")
    cur = conn.execute(
        "INSERT INTO logs (source, raw_line, received_at) "
        "VALUES ('test', 'x', datetime('now', ?))",
        (f"-{age_seconds} seconds",),
    )
    conn.execute(
        "INSERT INTO parsed_events (log_id, event_type, username, source_ip) "
        "VALUES (?, ?, ?, ?)",
        (cur.lastrowid, event_type, username, ip),
    )
    conn.commit()
    conn.close()


def add_many(n, event_type, ip, **kwargs):
    for _ in range(n):
        add_event(event_type, ip, **kwargs)


# ---- threshold ----------------------------------------------------------

def test_below_threshold_returns_nothing(db):
    add_many(4, "invalid_user", "1.2.3.4")
    assert check_threshold_rule("invalid_user", 5, 3600) == []


def test_exactly_at_threshold_matches(db):
    # the rule is ">= threshold", not "> threshold"
    add_many(5, "invalid_user", "1.2.3.4")
    assert check_threshold_rule("invalid_user", 5, 3600) == [("1.2.3.4", 5)]


def test_above_threshold_reports_the_real_count(db):
    add_many(9, "invalid_user", "1.2.3.4")
    assert check_threshold_rule("invalid_user", 5, 3600) == [("1.2.3.4", 9)]


def test_empty_database_returns_nothing(db):
    assert check_threshold_rule("invalid_user", 1, 3600) == []


# ---- event type ---------------------------------------------------------

def test_only_the_requested_event_type_counts(db):
    add_many(3, "invalid_user", "1.2.3.4")
    add_many(3, "disconnected", "1.2.3.4")
    # 3 + 3 would pass a threshold of 5 if the types were mixed together
    assert check_threshold_rule("invalid_user", 5, 3600) == []
    assert check_threshold_rule("invalid_user", 3, 3600) == [("1.2.3.4", 3)]


# ---- time window --------------------------------------------------------

def test_events_outside_the_window_are_ignored(db):
    add_many(5, "invalid_user", "1.2.3.4", age_seconds=2 * 3600)
    assert check_threshold_rule("invalid_user", 1, 3600) == []


def test_window_boundary(db):
    add_event("invalid_user", "1.2.3.4", age_seconds=3500)   # inside a 3600 s window
    add_event("invalid_user", "1.2.3.4", age_seconds=3700)   # just outside it
    assert check_threshold_rule("invalid_user", 1, 3600) == [("1.2.3.4", 1)]


def test_window_size_changes_the_result(db):
    add_many(5, "invalid_user", "1.2.3.4", age_seconds=600)
    assert check_threshold_rule("invalid_user", 5, 3600) == [("1.2.3.4", 5)]
    assert check_threshold_rule("invalid_user", 5, 300) == []


# ---- grouping -----------------------------------------------------------

def test_group_by_ip_only_returns_ips_over_the_threshold(db):
    add_many(6, "invalid_user", "1.1.1.1")
    add_many(2, "invalid_user", "2.2.2.2")
    assert check_threshold_rule("invalid_user", 5, 3600) == [("1.1.1.1", 6)]


def test_group_by_ip_does_not_add_ips_together(db):
    # 3 + 3 = 6 overall, but no single IP reached 5
    add_many(3, "invalid_user", "1.1.1.1")
    add_many(3, "invalid_user", "2.2.2.2")
    assert check_threshold_rule("invalid_user", 5, 3600) == []


def test_group_by_ip_returns_every_ip_that_qualifies(db):
    add_many(5, "invalid_user", "1.1.1.1")
    add_many(7, "invalid_user", "2.2.2.2")
    assert sorted(check_threshold_rule("invalid_user", 5, 3600)) == [
        ("1.1.1.1", 5), ("2.2.2.2", 7)]


def test_no_grouping_counts_everything_together(db):
    add_many(3, "invalid_user", "1.1.1.1")
    add_many(3, "invalid_user", "2.2.2.2")
    # one overall row of (count,), not (ip, count)
    assert check_threshold_rule("invalid_user", 5, 3600, group_by_ip=False) == [(6,)]


def test_no_grouping_below_threshold_returns_nothing(db):
    add_many(2, "invalid_user", "1.1.1.1")
    assert check_threshold_rule("invalid_user", 5, 3600, group_by_ip=False) == []


# ---- distinct_column ----------------------------------------------------

def test_distinct_column_counts_unique_values_not_rows(db):
    add_many(10, "invalid_user", "1.1.1.1", username="admin")   # 10 rows, 1 name
    assert check_threshold_rule("invalid_user", 2, 3600, distinct_column="username") == []


def test_distinct_column_matches_when_enough_different_values(db):
    for name in ["admin", "root", "test", "oracle", "git"]:
        add_event("invalid_user", "1.1.1.1", username=name)
    assert check_threshold_rule("invalid_user", 5, 3600, distinct_column="username") == [
        ("1.1.1.1", 5)]


# ---- username filter ----------------------------------------------------

def test_username_filter_counts_only_that_account(db):
    add_many(3, "disconnected", "1.1.1.1", username="root")
    add_many(4, "disconnected", "1.1.1.1", username="admin")
    assert check_threshold_rule("disconnected", 3, 3600, username="root") == [("1.1.1.1", 3)]
    assert check_threshold_rule("disconnected", 4, 3600, username="root") == []


def test_username_filter_works_without_grouping(db):
    add_many(3, "disconnected", "1.1.1.1", username="root")
    add_many(3, "disconnected", "2.2.2.2", username="root")
    add_many(5, "disconnected", "3.3.3.3", username="admin")
    assert check_threshold_rule("disconnected", 5, 3600, group_by_ip=False, username="root") == [(6,)]


def test_username_is_a_value_not_sql(db):
    # the username goes through a ? placeholder, so a quote can't break the query
    add_many(3, "disconnected", "1.1.1.1", username="root")
    assert check_threshold_rule("disconnected", 1, 3600, username="x' OR '1'='1") == []