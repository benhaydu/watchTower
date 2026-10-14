# Watchtower

[![tests](https://github.com/benhaydu/watchTower/actions/workflows/tests.yaml/badge.svg)](https://github.com/benhaydu/watchTower/actions/workflows/tests.yaml)

A small SIEM (security information and event management) system I built to learn how detection pipelines work. It runs on an internet-exposed cloud VM, collects the SSH authentication log, turns raw log lines into structured events, runs detection rules over them, and shows the results on a live dashboard.

The server is not a honeypot simulation. It is a real VM with a real public IP, so everything the system sees is real attack traffic: hundreds of distinct scanners a day.


## How it works

```
sshd -> /var/log/auth.log -> collector -> POST /ingest (FastAPI, localhost only, API key)
     -> logs table -> parser -> parsed_events table
     -> rules engine (every 60 s) -> alerts table
     -> /stats and /alerts -> dashboard

cron (every 5 min) -> healthcheck -> healthchecks.io -> email if the pipeline goes quiet
```

| Component | What it does |
|---|---|
| `collector.py` | Tails `auth.log` by byte offset, batches lines, sends them to the API. Handles log rotation (inode change or file shrinking). |
| `parser.py` | Classifies each line into one of 14 event types with ordered regex patterns. Anything unrecognised is stored as `unknown`, which doubles as a health metric. |
| `database.py` | SQLite storage and all the queries: threshold checks, alert deduplication, dashboard aggregates. |
| `rules_engine.py` + `rules.yaml` | Threshold rules defined in YAML, evaluated by an in-process scheduler (APScheduler). |
| `app.py` | FastAPI service: `/ingest`, `/alerts`, `/stats`, `/dashboard`. Endpoints require an `X-API-Key` header. |
| `static/dashboard.html` | A single-file dashboard (plain HTML/JS plus Chart.js). Auto-refreshes every 30 seconds. |
| `healthcheck.py` | A dead-man's switch: checks the services and data freshness, and pings healthchecks.io. |

## Detection rules

The server has password authentication disabled, so scanners are rejected before any password is tried and there are almost no failed-password events. The rules therefore target pre-authentication behaviour instead:

| Rule | Fires when |
|---|---|
| `username_enumeration` | an IP tries 5 or more invalid usernames within an hour |
| `persistent_scanner` | an IP produces 20 or more disconnects within an hour |
| `auth_limit_hit` | an IP exhausts the allowed authentication attempts |

Each (rule, IP) pair alerts at most once per window, so one noisy scanner does not flood the alerts table.

## What I learned from it

- **Silent failures are the real enemy.** The pipeline broke quietly twice: a bad deploy took both services down for a week, and a log rotation left the collector "running" but reading nothing. Both were only noticed by manually checking. The answer was monitoring the *output* (is fresh data arriving?) rather than the process (is the service up?), with an external dead-man's switch that still alerts when the whole VM is dead.
- **Parse real data, not assumed data.** My first parser left about half of all events as `unknown`. Real attackers send empty usernames, usernames with spaces and HTML fragments, and unusual line formats. Regexes written from the documentation did not match what the server actually logs.
- **Write rules for the traffic you actually have.** My first four rules assumed failed-password events that this server can never produce. I replaced them with rules based on what the data showed.
- **Treat log data as hostile.** Usernames are attacker-controlled, so the dashboard renders them as text, never as HTML.

## Running it

Requirements: Python 3.12.

```bash
pip install -r requirements.txt
python -m pytest -q          # run the tests
cd src
uvicorn app:app --host 127.0.0.1 --port 8000
```

Configuration is through environment variables (API key, log file path, database path); see the source for the names. The API listens on localhost only, and the dashboard is reached through an SSH tunnel rather than being exposed publicly.

## Status

Working and deployed: collection, parsing, three detection rules, dashboard, and health monitoring.

Planned: an alert for successful logins from unfamiliar IPs, IP enrichment (country and network), a Go rewrite of the collector, and anomaly detection.