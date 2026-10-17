import sqlite3

import pytest

from database import init_db, get_stats

MY_IP = "203.0.113.50"


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Fresh empty database in a temp folder, with MY_IP as the only known IP."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WATCHTOWER_IGNORE_IPS", MY_IP)
    init_db()


def add_event(event_type, ip=None, username=None, n=1):
    """Insert n parsed_events rows (get_stats' top lists don't need a logs row)."""
    conn = sqlite3.connect("app_database.db")
    for _ in range(n):
        conn.execute(
            "INSERT INTO parsed_events (event_type, username, source_ip) VALUES (?, ?, ?)",
            (event_type, username, ip),
        )
    conn.commit()
    conn.close()


def as_dict(rows):
    return {r["label"]: r["count"] for r in rows}


# ---- top_ips ------------------------------------------------------------

def test_top_ips_counts_every_hostile_event_type(db):
    add_event("invalid_user", "1.1.1.1", "admin", n=2)
    add_event("connection_closed", "1.1.1.1", "root", n=3)
    add_event("disconnected", "1.1.1.1", "root", n=1)
    assert as_dict(get_stats()["top_ips"]) == {"1.1.1.1": 6}


def test_top_ips_excludes_my_own_ip(db):
    add_event("disconnected", MY_IP, "ubuntu", n=5)
    add_event("invalid_user", "1.1.1.1", "admin")
    assert as_dict(get_stats()["top_ips"]) == {"1.1.1.1": 1}


def test_top_ips_lookalike_of_my_ip_is_still_counted(db):
    # exact match, not substring: 203.0.113.5 and 203.0.113.500-style neighbours are not me
    add_event("invalid_user", "203.0.113.5", "admin")
    add_event("invalid_user", "3.0.113.50", "admin")
    assert as_dict(get_stats()["top_ips"]) == {"203.0.113.5": 1, "3.0.113.50": 1}


def test_top_ips_excludes_login_and_system_event_types(db):
    add_event("accepted_publickey", "1.1.1.1", "ubuntu")
    add_event("accepted_password", "1.1.1.1", "ubuntu")
    add_event("sudo_command", "1.1.1.1", "ubuntu")
    add_event("system_session", "1.1.1.1")
    assert get_stats()["top_ips"] == []


def test_top_ips_skips_events_without_an_ip(db):
    add_event("protocol_error", None)
    assert get_stats()["top_ips"] == []


def test_top_ips_is_ordered_and_limited(db):
    add_event("invalid_user", "1.1.1.1", "a", n=1)
    add_event("invalid_user", "2.2.2.2", "a", n=3)
    add_event("invalid_user", "3.3.3.3", "a", n=2)
    top = get_stats(top_n=2)["top_ips"]
    assert [r["label"] for r in top] == ["2.2.2.2", "3.3.3.3"]


def test_top_ips_works_with_no_ignore_list(db, monkeypatch):
    # empty -> `NOT IN ()` must not break the query or hide rows
    monkeypatch.delenv("WATCHTOWER_IGNORE_IPS")
    add_event("invalid_user", MY_IP, "admin")
    assert as_dict(get_stats()["top_ips"]) == {MY_IP: 1}


def test_top_ips_handles_several_ignored_ips(db, monkeypatch):
    monkeypatch.setenv("WATCHTOWER_IGNORE_IPS", f"{MY_IP}, 198.51.100.7")
    add_event("invalid_user", MY_IP, "admin")
    add_event("invalid_user", "198.51.100.7", "admin")
    add_event("invalid_user", "1.1.1.1", "admin")
    assert as_dict(get_stats()["top_ips"]) == {"1.1.1.1": 1}


# ---- top_usernames ------------------------------------------------------

def test_top_usernames_counts_names_attackers_tried(db):
    add_event("invalid_user", "1.1.1.1", "admin", n=2)
    add_event("connection_closed", "1.1.1.1", "root", n=3)   # real account: no invalid_user line
    assert as_dict(get_stats()["top_usernames"]) == {"admin": 2, "root": 3}


def test_top_usernames_excludes_my_logins_and_sudo(db):
    add_event("accepted_publickey", MY_IP, "ubuntu")
    add_event("accepted_password", "1.1.1.1", "ubuntu")
    add_event("sudo_command", None, "ubuntu")
    assert get_stats()["top_usernames"] == []


def test_top_usernames_excludes_events_from_my_ip(db):
    add_event("disconnected", MY_IP, "ubuntu", n=4)    # my own session ends
    add_event("disconnected", "1.1.1.1", "ubuntu", n=1)  # an attacker trying the same name
    assert as_dict(get_stats()["top_usernames"]) == {"ubuntu": 1}


def test_top_usernames_keeps_rows_that_have_no_ip(db):
    # NULL NOT IN (...) is NULL in SQL, which would silently drop these rows
    add_event("invalid_user", None, "ghost", n=2)
    assert as_dict(get_stats()["top_usernames"]) == {"ghost": 2}


def test_top_usernames_works_with_no_ignore_list(db, monkeypatch):
    monkeypatch.delenv("WATCHTOWER_IGNORE_IPS")
    add_event("invalid_user", "1.1.1.1", "admin")
    assert as_dict(get_stats()["top_usernames"]) == {"admin": 1}