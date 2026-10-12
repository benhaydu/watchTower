import sqlite3
import pytest
from database import (
    init_db, insert_logs, insert_parsed_logs,
    get_unknown_events, update_parsed_events,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A fresh, empty database in a temp folder. database.py opens
    "app_database.db" by relative path, so moving the working directory
    is enough to point every helper at this throwaway file."""
    monkeypatch.chdir(tmp_path)
    init_db()


def seed():
    """Two logs: row 1 is 'unknown', row 2 is already parsed as invalid_user.
    Returns their parsed_events ids (1 and 2 in a fresh DB)."""
    log_ids = insert_logs("test", [
        "sshd[1]: Received disconnect from 1.2.3.4 port 22:11: Bye Bye [preauth]",
        "sshd[2]: Invalid user admin from 5.6.7.8 port 40000",
    ])
    insert_parsed_logs(log_ids[0], "unknown", None, None, None)
    insert_parsed_logs(log_ids[1], "invalid_user", "admin", "5.6.7.8", 40000)
    return 1, 2


def all_rows():
    conn = sqlite3.connect("app_database.db")
    try:
        return conn.execute(
            "SELECT id, event_type, username, source_ip FROM parsed_events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def test_get_unknown_events_returns_only_unknown(db):
    seed()
    events = get_unknown_events()
    assert len(events) == 1
    assert events[0][0] == 1                      # parsed_events.id
    assert "Received disconnect" in events[0][1]  # logs.raw_line


def test_update_changes_unknown_rows(db):
    unknown_id, _ = seed()
    update_parsed_events([
        ("disconnected", None, "1.2.3.4", "22", None, None, unknown_id),
    ])
    assert all_rows()[0] == (1, "disconnected", None, "1.2.3.4")


def test_update_never_overwrites_a_known_row(db):
    """The `AND event_type = 'unknown'` guard: a wrong id must not clobber
    a row that was already parsed correctly."""
    _, known_id = seed()
    update_parsed_events([
        ("disconnected", None, "9.9.9.9", "22", None, None, known_id),
    ])
    assert all_rows()[1] == (2, "invalid_user", "admin", "5.6.7.8")


def test_update_is_all_or_nothing(db):
    """If one update in the batch is malformed, none are applied."""
    unknown_id, _ = seed()
    good = ("disconnected", None, "1.2.3.4", "22", None, None, unknown_id)
    bad = ("disconnected", None, "1.2.3.4")        # wrong number of values
    with pytest.raises(sqlite3.ProgrammingError):
        update_parsed_events([good, bad])
    assert all_rows()[0][1] == "unknown"           # the good one was rolled back