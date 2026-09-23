import os
import secrets
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, Header, HTTPException

from model import LogBatch, AlertOut
from database import init_db, insert_logs, insert_parsed_logs, get_alerts
from parser import parse
from rules_engine import run_rules

RULES_INTERVAL_SECONDS = 60

scheduler = BackgroundScheduler()

# Required, not defaulted -- fail loudly at import time rather than silently
# accepting unauthenticated /ingest traffic because someone forgot to set it.
API_KEY = os.environ["WATCHTOWER_API_KEY"]


def verify_api_key(x_api_key: str = Header(None)):
    # secrets.compare_digest instead of `!=`: a plain string comparison short-
    # circuits on the first mismatched character, so response time leaks how
    # many leading characters of the key an attacker guessed right (a timing
    # attack). compare_digest always takes the same time regardless.
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # APScheduler runs run_rules() on its own thread, so a slow rules pass
    # (SQLite queries) doesn't block the /ingest event loop.
    scheduler.add_job(run_rules, "interval", seconds=RULES_INTERVAL_SECONDS)
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(lifespan=lifespan)

@app.post("/ingest", dependencies=[Depends(verify_api_key)])
async def ingest(batch: LogBatch):
    log_ids = insert_logs(batch.source, batch.logs)

    for log_id, line in zip(log_ids, batch.logs):
        event_type, username, source_ip, port, target_user, command = parse(line)
        insert_parsed_logs(log_id, event_type, username, source_ip, port, target_user, command)

    return batch


@app.get("/alerts", response_model=list[AlertOut], dependencies=[Depends(verify_api_key)])
async def alerts(limit: int = 100):
    return get_alerts(limit)