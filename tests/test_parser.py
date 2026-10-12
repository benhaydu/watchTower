import pytest
from parser import parse

# parse() returns (event_type, username, source_ip, port, target_user, command)

def L(msg, proc="sshd[1000]"):
    """Wrap a message in the same prefix collector.py ships."""
    return f"2026-10-02T12:00:00.000000+00:00 watchtower-vm {proc}: {msg}"


# --- already worked before; these guard against regressions -------------
KNOWN_GOOD = [
    (L("Invalid user admin from 206.189.118.69 port 51188"),
     "invalid_user", "admin", "206.189.118.69", "51188"),
    (L("Failed password for invalid user test from 1.2.3.4 port 22 ssh2"),
     "failed_password", "test", "1.2.3.4", "22"),
    (L("Accepted publickey for ubuntu from 203.0.113.10 port 51821 ssh2"),
     "accepted_publickey", "ubuntu", "203.0.113.10", "51821"),
    (L("Connection closed by authenticating user root 41.204.63.118 port 46614 [preauth]"),
     "connection_closed", "root", "41.204.63.118", "46614"),
    (L("Connection reset by authenticating user root 41.204.63.118 port 46614 [preauth]"),
     "connection_reset", "root", "41.204.63.118", "46614"),
]

# --- currently broken: these should now map to the existing types -------
TO_FIX = [
    # Closed, invalid user (real lines from your unknowns)
    (L("Connection closed by invalid user admin 206.189.118.69 port 51188 [preauth]"),
     "connection_closed", "admin", "206.189.118.69", "51188"),
    (L("Connection closed by invalid user Administrator 200.105.141.172 port 40440 [preauth]"),
     "connection_closed", "Administrator", "200.105.141.172", "40440"),
    # Closed, no user at all
    (L("Connection closed by 193.112.192.91 port 47932"),
     "connection_closed", None, "193.112.192.91", "47932"),
    (L("Connection closed by 105.158.234.156 port 43478"),
     "connection_closed", None, "105.158.234.156", "43478"),
    # Reset variants (shapes built from the same sshd format)
    (L("Connection reset by invalid user admin 206.189.118.69 port 51188 [preauth]"),
     "connection_reset", "admin", "206.189.118.69", "51188"),
    (L("Connection reset by 193.112.192.91 port 47932 [preauth]"),
     "connection_reset", None, "193.112.192.91", "47932"),
    # Attacker-controlled usernames (constructed from the shapes in your query output;
    # swap in your real lines with: SELECT raw_line ... WHERE raw_line LIKE '%Invalid user  from%')
    (L("Invalid user  from 61.1.2.3 port 5000"),
     "invalid_user", None, "61.1.2.3", "5000"),
    (L("Invalid user <html style=x> from 61.1.2.3 port 5000"),
     "invalid_user", "<html style=x>", "61.1.2.3", "5000"),
]


@pytest.mark.parametrize("line,etype,user,ip,port", KNOWN_GOOD + TO_FIX)
def test_parse_fields(line, etype, user, ip, port):
    event_type, username, source_ip, p, _target, _cmd = parse(line)
    assert event_type == etype
    assert username == user
    assert source_ip == ip
    assert p == port


# --- families that are 'unknown' today. Once you've chosen type names,
#     replace "!= unknown" with the exact type you picked. ---------------
NEW_FAMILIES = [
    L("Received disconnect from 129.121.116.121 port 47040:11: Bye Bye [preauth]"),
    L("Disconnected from authenticating user root 41.204.63.118 port 46614 [preauth]"),
    L("Disconnected from invalid user ismail 129.121.139.106 port 35666 [preauth]"),
    L("banner exchange: Connection from 152.32.207.234 port 60256: invalid format"),
    L("error: maximum authentication attempts exceeded for invalid user usuario "
      "from 79.104.197.202 port 52696 ssh2 [preauth]"),
    L("Disconnecting authenticating user root 1.2.3.4 port 22: "
      "Too many authentication failures [preauth]"),
]

@pytest.mark.xfail(reason="new families not parsed yet", strict=False)
@pytest.mark.parametrize("line", NEW_FAMILIES)
def test_new_families_not_unknown(line):
    assert parse(line)[0] != "unknown"


# --- noise we may decide to ignore on purpose -----------------------------
def test_cron_session_is_still_unknown_for_now():
    line = L("pam_unix(cron:session): session closed for user root", proc="CRON[196399]")
    assert parse(line)[0] == "unknown"