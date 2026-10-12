"""
Parses raw auth-log lines into structured events.

Handles the OpenSSH sshd line types watchtower's rules care about:

    Failed password for admin from 203.0.113.10 port 51821 ssh2
    Failed password for invalid user admin from 203.0.113.10 port 51821 ssh2
    Accepted password for ubuntu from 203.0.113.10 port 51821 ssh2
    Accepted publickey for ubuntu from 203.0.113.10 port 51821 ssh2
    Invalid user admin from 203.0.113.10 port 51821
    Connection reset by authenticating user ubuntu 203.0.113.10 port 22
    Connection closed by authenticating user ubuntu 203.0.113.10 port 22
    sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update

Add more compiled patterns + PATTERNS entries as you support more event types.
"""

import re
from collections import Counter
from database import (
    get_unparsed_logs, insert_parsed_logs,
    get_unknown_events, update_parsed_events,
)

IP = r"(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
PORT = r"(?P<port>\d+)"
USER = r"(?P<username>\S+)"
LOOSE_USER = r"(?P<username>.*?)"

PATTERNS = [
    ("failed_password", rf"Failed password for (?:invalid user )?{USER} from {IP} port {PORT}"),

    ("accepted_password", rf"Accepted password for {USER} from {IP} port {PORT}"),

    ("accepted_publickey", rf"Accepted publickey for {USER} from {IP} port {PORT}"),

    ("invalid_user", rf"Invalid user (?P<username>(?:(?! from ).)*) from {IP} port {PORT}"),

    ("connection_reset", rf"Connection reset by (?:(?:authenticating|invalid) user {LOOSE_USER} )?{IP} port {PORT}"),

    ("connection_closed", rf"Connection closed by (?:(?:authenticating|invalid) user {LOOSE_USER} )?{IP} port {PORT}"),

    ("sudo_command", r"sudo:\s*(?P<username>\S+)\s*:.*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"),

    ("disconnected", rf"(?:Received disconnect|Disconnected) from (?:(?:(?:authenticating|invalid) )?user {LOOSE_USER} )?{IP} port {PORT}"),

    ("bad_banner", rf"banner exchange: Connection from {IP} port {PORT}: (?:invalid format|could not read protocol version)"),

    ("too_many_auth", rf"maximum authentication attempts exceeded for (?:invalid user )?{USER} from {IP} port {PORT}"),
    ("too_many_auth", rf"Disconnecting (?:authenticating|invalid) user {USER} {IP} port {PORT}: Too many authentication failures"),

    ("protocol_error", rf"Unable to negotiate with {IP} port {PORT}:"),
    ("protocol_error", rf"error: (?:kex_exchange_identification|kex_protocol_error|Protocol major versions differ)"),
    ("protocol_error", rf"fatal: userauth_pubkey"),


    ("maxstartups", rf"(?:beginning|exited) MaxStartups throttling"),
    ("maxstartups", rf"drop connection #\d+ from \[{IP}\]:{PORT} on"),

    ("system_session", rf"pam_unix\((?:cron|sudo|sshd):session\)"),
    ("system_session", rf"New session \d+ of user"),
    ("system_session", rf"Session \d+ logged out"),
    ("system_session", rf"Removed session \d+"),





]


def parse(line):
    for event_type, pattern in PATTERNS:
        match = re.search(pattern, line)
        if match:
            fields = match.groupdict()
            return (
                event_type,
                fields.get("username") or None,
                fields.get("source_ip"),
                fields.get("port"),
                fields.get("target_user"),
                fields.get("command"),
            )

    return "unknown", None, None, None, None, None

def reparse_unknown(dry_run=True):
    events = get_unknown_events()
    updates = []
    counts = Counter()
    leftovers = []                                   # CHANGE 1: new list, before the loop

    for event_id, raw_line in events:
        parsed_line = parse(raw_line)
        counts[parsed_line[0]] += 1
        if parsed_line[0] != "unknown":
            updates.append(parsed_line + (event_id,))
        else:                                        # CHANGE 2: collect the unparsed lines
            leftovers.append(raw_line)

    print(f"Examined {len(events)} unknown rows:")
    for event_type, n in counts.most_common():
        label = "still unknown" if event_type == "unknown" else event_type
        print(f"  {label:<18} {n}")                  # 16 -> 18 so connection_closed lines up

    for line in leftovers[:30]:                      # CHANGE 3: print them, after the counts
        print("  ?", line)

    if dry_run:
        print(f"DRY RUN: would update {len(updates)} rows. Nothing was changed.")
    else:
        update_parsed_events(updates)
        print(f"Updated {len(updates)} rows.")

def run_parser():
    """Manual backfill/debug tool: parses any rows already in `logs` that
    don't yet have a matching `parsed_events` row. Not used by the live
    /ingest path (app.py parses each batch immediately), kept for backfill
    and debugging."""
    unparsed = get_unparsed_logs()
    print(f"Found {len(unparsed)} unparsed log(s)")
    for row in unparsed:
        log_id, raw_line = row
        event_type, username, source_ip, port, target_user, command = parse(raw_line)
        print(f"log_id {log_id}: {event_type} | user={username} ip={source_ip} port={port} "
              f"target_user={target_user} command={command}")
        insert_parsed_logs(log_id, event_type, username, source_ip, port, target_user, command)


if __name__ == "__main__":
    import sys
    if "--reparse" in sys.argv:
        reparse_unknown(dry_run="--apply" not in sys.argv)
    else:
        run_parser()
