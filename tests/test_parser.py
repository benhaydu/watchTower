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
# (line, expected_type, expected_username, expected_ip, expected_port)
NEW_CASES = [
    (L("banner exchange: Connection from 45.56.103.154 port 62566: could not read protocol version"),
     "bad_banner", None, "45.56.103.154", "62566"),
    (L("Connection closed by invalid user  47.250.81.7 port 14312 [preauth]"),
     "connection_closed", None, "47.250.81.7", "14312"),
    (L('Connection closed by invalid user <html style="height 43.156.91.175 port 51422 [preauth]'),
     "connection_closed", '<html style="height', "43.156.91.175", "51422"),
    (L("Disconnected from user ubuntu 38.143.207.199 port 54960"),
     "disconnected", "ubuntu", "38.143.207.199", "54960"),
    (L("exited MaxStartups throttling after 00:00:40, 5 connections dropped"),
     "maxstartups", None, None, None),
]

@pytest.mark.parametrize("line,etype,user,ip,port", NEW_CASES)
def test_new_families(line, etype, user, ip, port):
    event_type, username, source_ip, p, _t, _c = parse(line)
    assert (event_type, username, source_ip, p) == (etype, user, ip, port)

def test_unrelated_line_with_ip_and_port_stays_unknown():
    line = L("Some other message from 1.2.3.4 port 22 that no pattern knows")
    assert parse(line)[0] == "unknown"

def test_unrelated_error_line_is_not_protocol_error():
    line = L("error: something sshd has never said before")
    assert parse(line)[0] == "unknown"