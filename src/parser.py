import re
import time
from database import get_unparsed_logs, insert_parsed_logs

IP = r"(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
PORT = r"(?P<port>\d+)"
USER = r"(?P<username>\S+)"

PATTERNS = [
    # "invalid user" is an optional prefix here (rather than a separate pattern)
    # so a failed login against a nonexistent account still counts as event_type
    # failed_password -- brute_force/credential_stuffing rules should treat it
    # the same as any other failed attempt.
    ("failed_password", rf"Failed password for (?:invalid user )?{USER} from {IP} port {PORT}"),
    ("accepted_password", rf"Accepted password for {USER} from {IP} port {PORT}"),
    ("accepted_publickey", rf"Accepted publickey for {USER} from {IP} port {PORT}"),
    # Distinct from failed_password: sshd logs this BEFORE any password is even
    # checked, when the username itself doesn't exist locally -- useful as a
    # username-enumeration signal on its own.
    ("invalid_user", rf"Invalid user {USER} from {IP} port {PORT}"),
    ("connection_reset", rf"Connection reset by authenticating user {USER} {IP} port {PORT}"),
    ("connection_closed", rf"Connection closed by authenticating user {USER} {IP} port {PORT}"),
    # Local privilege escalation -- no source_ip/port (it's not a network event),
    # but captures which account was escalated TO and what was run.
    ("sudo_command", r"sudo:\s*(?P<username>\S+)\s*:.*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"),
]

def parse(line):
    for event_type, pattern in PATTERNS:
        match = re.search(pattern, line)
        if match:
            fields = match.groupdict()
            return (
                event_type,
                fields.get("username"),
                fields.get("source_ip"),
                fields.get("port"),
                fields.get("target_user"),
                fields.get("command"),
            )

    return "unknown", None, None, None, None, None

def run_parser():
    unparsed = get_unparsed_logs()
    print(f"Found {len(unparsed)} unparsed log(s)")
    for row in unparsed:
        log_id, raw_line = row
        event_type, username, source_ip, port, target_user, command = parse(raw_line)
        print(f"log_id {log_id}: {event_type} | user={username} ip={source_ip} port={port} "
              f"target_user={target_user} command={command}")
        insert_parsed_logs(log_id, event_type, username, source_ip, port, target_user, command)
        

if __name__ == "__main__":
    run_parser()