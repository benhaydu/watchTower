"""
Parses raw auth-log lines into structured event dicts.

Currently handles OpenSSH sshd "Failed password" lines, matching what
collector.py tails from test_auth.log:

    2026-09-21T20:01:15-07:00 watchtower-vm sshd[8001]: Failed password for admin from 203.0.113.10 port 51821 ssh2
    2026-09-21T20:01:28-07:00 watchtower-vm sshd[8001]: Failed password for root from 198.51.100.150 port 22001 ssh2

Add more compiled patterns + PARSERS entries as you support more event types
(e.g. "Accepted password", "Invalid user", sudo events, etc.).
"""

import re

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>\S+) port (?P<port>\d+)"
)

# Ordered list of (event_type, compiled pattern). First match wins.
PARSERS = [
    ("failed_password", FAILED_PASSWORD_PATTERN),
]


def parse_line(raw_line: str) -> dict | None:
    """
    Parse a single raw log line into a structured event.

    Returns a dict with keys: event_type, username, source_ip, port
    or None if the line doesn't match any known pattern.
    """
    for event_type, pattern in PARSERS:
        match = pattern.search(raw_line)
        if match:
            return {
                "event_type": event_type,
                "username": match.group("username"),
                "source_ip": match.group("source_ip"),
                "port": int(match.group("port")),
            }
    return None
