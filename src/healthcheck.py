import os, sqlite3, subprocess, urllib.request
from datetime import datetime, timezone

DB_PATH = "/home/ubuntu/watchTower/src/app_database.db"
MAX_AGE_MINUTES = 20
SERVICES = ["watchtower-app", "watchtower-collector"]
PING_URL = os.environ["WATCHTOWER_HEALTHCHECK_URL"]   # from the env file, never hardcoded

def newest_event_age_minutes():
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT MAX(received_at) FROM logs")
        row = cursor.fetchone()

        if row[0] is None:
            return None

        last_received_str = row[0]
        last_received = datetime.fromisoformat(last_received_str).replace(tzinfo=timezone.utc)
        

        now_utc = datetime.now(timezone.utc)
        time_delta = now_utc - last_received

        return time_delta.total_seconds() / 60.0
    finally:
        conn.close()


def service_is_active(name):
    result = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=10)
    if result.stdout.strip() == "active":
        return True

    return False



def ping(suffix="", message=None):
    data = None                      # default: a plain GET with no body
    if message:
        data = message.encode()      # a body turns it into a POST; shows up in the alert
    try:
        with urllib.request.urlopen(PING_URL + suffix, data=data, timeout=10):
            pass
    except OSError as e:
        print(f"ping failed: {e}")
    

def main():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    problems = []

    for name in SERVICES:
        if not service_is_active(name):
            problems.append(f"{name} is not active")

    age = newest_event_age_minutes()
    if age is None:
        problems.append("no events in the database")
    elif age > MAX_AGE_MINUTES:
        problems.append(f"newest event is {age:.0f} min old (limit {MAX_AGE_MINUTES})")

    if problems:
        message = "; ".join(problems)
        print(f"{now} UNHEALTHY: {message}")     # cron appends this to the log
        ping("/fail", message)                   # healthchecks.io alerts right away
    else:
        print(f"{now} OK: newest event {age:.1f} min old")
        ping()                                   # normal "still alive" ping

if __name__ == "__main__":
    main()