from pathlib import Path

import pytest

from database import (
    init_db, insert_logs, insert_parsed_logs, get_alerts,
)
from rules_engine import load_rules, run_rules

# The two login rules, exactly as they appear in src/rules.yaml. The tests
# write their own copy into a temp folder so they control the rules and never
# depend on (or break when someone tunes) the real thresholds.
LOGIN_RULES_YAML = """\
rules:
  - name: ssh_login
    event_type: accepted_publickey
    threshold: 1
    window_seconds: 3600
    group_by_ip: true
    ignore_known_ips: true

  - name: password_login
    event_type: accepted_password
    threshold: 1
    window_seconds: 3600
    group_by_ip: true
"""

KNOWN_IP = "38.143.207.199"
STRANGER_IP = "203.0.113.50"


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A fresh database AND a rules.yaml in a temp folder. database.py and
    run_rules() both open their files by relative path, so changing the
    working directory points everything at these throwaway copies.
    The env var is cleared so each test starts with 'no known IPs'."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WATCHTOWER_IGNORE_IPS", raising=False)
    (tmp_path / "rules.yaml").write_text(LOGIN_RULES_YAML)
    init_db()


def seed_login(event_type, ip, username="ubuntu"):
    """One successful-login event from `ip`. The logs row gets
    received_at = now automatically, so it falls inside the 3600 s window."""
    log_ids = insert_logs("test", [f"sshd[1]: {event_type} for {username} from {ip} port 50000"])
    insert_parsed_logs(log_ids[0], event_type, username, ip, 50000)


def test_login_from_unknown_ip_alerts(db):
    """Env var unset (the fixture clears it) must mean 'ignore nothing'."""
    seed_login("accepted_publickey", STRANGER_IP)
    run_rules()
    alerts = get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "ssh_login"
    assert alerts[0]["matched_entity"] == STRANGER_IP


def test_login_from_known_ip_is_ignored(db, monkeypatch):
    monkeypatch.setenv("WATCHTOWER_IGNORE_IPS", KNOWN_IP)
    seed_login("accepted_publickey", KNOWN_IP)
    run_rules()
    assert get_alerts() == []


def test_known_ip_list_tolerates_spaces_and_multiple_entries(db, monkeypatch):
    """'1.1.1.1, 2.2.2.2 ,' must parse to two IPs (spaces stripped, empty
    trailing entry dropped), and a third IP must still alert."""
    monkeypatch.setenv("WATCHTOWER_IGNORE_IPS", "1.1.1.1, 2.2.2.2 ,")
    seed_login("accepted_publickey", "1.1.1.1")
    seed_login("accepted_publickey", "2.2.2.2")
    seed_login("accepted_publickey", STRANGER_IP)
    run_rules()
    assert [a["matched_entity"] for a in get_alerts()] == [STRANGER_IP]


@pytest.mark.parametrize("lookalike", [
    "38.143.207.19",    # a prefix of the known IP
    "8.143.207.199",    # a suffix of the known IP
])
def test_lookalike_ip_is_not_treated_as_known(db, monkeypatch, lookalike):
    """Regression test: ignoring must be an exact match, not a substring
    check. With `ip in "38.143.207.199"` (a plain string) both of these
    would have been silently ignored."""
    monkeypatch.setenv("WATCHTOWER_IGNORE_IPS", KNOWN_IP)
    seed_login("accepted_publickey", lookalike)
    run_rules()
    alerts = get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["matched_entity"] == lookalike


def test_password_login_alerts_even_from_a_known_ip(db, monkeypatch):
    """Password auth is disabled on the server, so ANY accepted_password is
    a tripwire. The ignore list must not apply to it."""
    monkeypatch.setenv("WATCHTOWER_IGNORE_IPS", KNOWN_IP)
    seed_login("accepted_password", KNOWN_IP)
    run_rules()
    alerts = get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "password_login"
    assert alerts[0]["matched_entity"] == KNOWN_IP


def test_repeat_run_does_not_duplicate_the_alert(db):
    """The rules run every minute; the same login must alert once per window."""
    seed_login("accepted_publickey", STRANGER_IP)
    run_rules()
    run_rules()
    assert len(get_alerts()) == 1


def test_real_rules_yaml_has_the_login_rules():
    """Guards the real config against typos and against someone removing the
    ignore flag from ssh_login or adding it to password_login."""
    rules_path = Path(__file__).resolve().parent.parent / "src" / "rules.yaml"
    by_name = {r["name"]: r for r in load_rules(str(rules_path))}
    assert by_name["ssh_login"]["event_type"] == "accepted_publickey"
    assert by_name["ssh_login"]["ignore_known_ips"] is True
    assert by_name["password_login"]["event_type"] == "accepted_password"
    assert not by_name["password_login"].get("ignore_known_ips")