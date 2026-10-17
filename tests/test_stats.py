import sqlite3

import pytest

from database import init_db, insert_alert, get_stats


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Fresh empty database in a temp folder (database.py opens
    "app_database.db" by relative path)."""
    monkeypatch.chdir(tmp_path)
    init_db()


def set_triggered_at(alert_id, when_sql):
    """insert_alert() always stamps 'now'; to test the 7-day cutoff we
    rewrite one row's timestamp directly."""
    conn = sqlite3.connect("app_database.db")
    conn.execute(f"UPDATE alerts SET triggered_at = {when_sql} WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()


def test_tripwires_empty_when_no_login_alerts(db):
    insert_alert("username_enumeration", "1.2.3.4", 6, 3600)
    assert get_stats()["tripwires"] == []


def test_tripwires_contains_only_the_tripwire_rules(db):
    insert_alert("username_enumeration", "1.2.3.4", 6, 3600)
    insert_alert("persistent_scanner", "5.6.7.8", 25, 3600)
    insert_alert("ssh_login", "203.0.113.50", 1, 3600)
    insert_alert("password_login", "203.0.113.51", 1, 3600)
    tripwires = get_stats()["tripwires"]
    assert {t["rule_name"] for t in tripwires} == {"ssh_login", "password_login"}


def test_tripwires_row_shape(db):
    insert_alert("ssh_login", "203.0.113.50", 1, 3600)
    row = get_stats()["tripwires"][0]
    assert set(row) == {"rule_name", "matched_entity", "triggered_at"}
    assert row["matched_entity"] == "203.0.113.50"


def test_tripwires_newest_first(db):
    insert_alert("ssh_login", "203.0.113.1", 1, 3600)    # id 1: made older below
    insert_alert("ssh_login", "203.0.113.2", 1, 3600)    # id 2: stays 'now'
    set_triggered_at(1, "datetime('now', '-2 days')")
    ips = [t["matched_entity"] for t in get_stats()["tripwires"]]
    assert ips == ["203.0.113.2", "203.0.113.1"]


def test_tripwires_ignore_alerts_older_than_the_window(db):
    insert_alert("ssh_login", "203.0.113.1", 1, 3600)
    set_triggered_at(1, "datetime('now', '-10 days')")
    assert get_stats()["tripwires"] == []