import importlib

import pytest
from fastapi.testclient import TestClient

from database import init_db, insert_alert, insert_logs, insert_parsed_logs

KEY = "test-key"
HEADERS = {"X-API-Key": KEY}


class FakeReader:
    """Same .get(ip) contract as a maxminddb Reader, no .mmdb file needed."""

    def __init__(self, records):
        self.records = records

    def get(self, ip):
        if not isinstance(ip, str):
            raise TypeError("argument must be a string")
        return self.records.get(ip)


COUNTRY = FakeReader({"8.8.8.8": {"country": {"iso_code": "US"}}})
ASN = FakeReader({"8.8.8.8": {"autonomous_system_number": 15169,
                              "autonomous_system_organization": "Google LLC"}})


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Fresh empty database in a temp folder (database.py uses a relative path)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WATCHTOWER_IGNORE_IPS", raising=False)
    init_db()


@pytest.fixture
def app_module(db, monkeypatch):
    """app.py reads WATCHTOWER_API_KEY at import time and opens the GeoIP files
    at import time, so set the environment first, then (re)import it, then swap
    in the fake readers."""
    monkeypatch.setenv("WATCHTOWER_API_KEY", KEY)
    monkeypatch.delenv("WATCHTOWER_GEOIP_COUNTRY_DB", raising=False)
    monkeypatch.delenv("WATCHTOWER_GEOIP_ASN_DB", raising=False)
    module = importlib.reload(importlib.import_module("app"))
    monkeypatch.setattr(module, "COUNTRY_READER", COUNTRY)
    monkeypatch.setattr(module, "ASN_READER", ASN)
    return module


@pytest.fixture
def client(app_module):
    # No `with` block: that would run the lifespan and start the rules scheduler.
    return TestClient(app_module.app)


def add_event(ip, event_type="invalid_user"):
    (log_id,) = insert_logs("test", ["raw line"])
    insert_parsed_logs(log_id, event_type, "root", ip, 22)


# ---- /alerts ----

def test_alerts_carry_geo_fields(client):
    insert_alert("username_enumeration", "8.8.8.8", 6, 3600)
    row = client.get("/alerts", headers=HEADERS).json()[0]
    assert row["country"] == "US"
    assert row["asn"] == 15169
    assert row["org"] == "Google LLC"


def test_alert_for_unknown_ip_has_null_geo_fields(client):
    insert_alert("username_enumeration", "10.0.0.1", 6, 3600)
    row = client.get("/alerts", headers=HEADERS).json()[0]
    assert (row["country"], row["asn"], row["org"]) == (None, None, None)


def test_alert_with_no_entity_does_not_break_the_endpoint(client):
    insert_alert("some_global_rule", None, 3, 3600)
    response = client.get("/alerts", headers=HEADERS)
    assert response.status_code == 200
    assert response.json()[0]["country"] is None


# ---- /stats ----

def test_top_ips_carry_geo_fields(client):
    add_event("8.8.8.8")
    row = client.get("/stats", headers=HEADERS).json()["top_ips"][0]
    assert row["label"] == "8.8.8.8"
    assert row["count"] == 1
    assert (row["country"], row["asn"], row["org"]) == ("US", 15169, "Google LLC")


def test_tripwires_carry_geo_fields(client):
    insert_alert("ssh_login", "8.8.8.8", 1, 3600)
    row = client.get("/stats", headers=HEADERS).json()["tripwires"][0]
    assert row["matched_entity"] == "8.8.8.8"
    assert (row["country"], row["asn"], row["org"]) == ("US", 15169, "Google LLC")


# ---- degraded and protected ----

def test_endpoints_still_work_when_geoip_files_are_missing(client, app_module, monkeypatch):
    monkeypatch.setattr(app_module, "COUNTRY_READER", None)
    monkeypatch.setattr(app_module, "ASN_READER", None)
    add_event("8.8.8.8")
    insert_alert("ssh_login", "8.8.8.8", 1, 3600)

    stats = client.get("/stats", headers=HEADERS)
    alerts = client.get("/alerts", headers=HEADERS)

    assert stats.status_code == 200 and alerts.status_code == 200
    assert stats.json()["top_ips"][0]["country"] is None
    assert stats.json()["tripwires"][0]["org"] is None
    assert alerts.json()[0]["asn"] is None


def test_stats_and_alerts_still_require_the_api_key(client):
    assert client.get("/stats").status_code == 401
    assert client.get("/alerts").status_code == 401