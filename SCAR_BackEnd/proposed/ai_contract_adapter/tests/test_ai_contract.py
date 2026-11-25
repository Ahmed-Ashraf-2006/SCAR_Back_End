"""Tests for the PROPOSED AI-contract adapter (root paths, X-API-Key). Original tests are untouched.
These use the adapter's own in-memory DB; they are NOT proof of a live n8n / AI-service run."""
import os

os.environ.setdefault("API_TOKEN", "test-token")
os.environ.setdefault("SECURITY_TOKEN", "sec-token")
os.environ.setdefault("AI_TOKEN", "ai-token")

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import config
from app.ai_contract_models import AIEvent
from app.database import Base, get_db
from app.main import app

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
KEY = {"X-API-Key": "ai-key-for-tests"}

EVENT = {  # same shape as the AI repo's docs/examples/event_rogue_ap.json
    "event_id": "10a3d6b2-aa05-411a-b271-5945795e8229", "mission_id": "mission-demo-001", "source": "drone",
    "event_type": "wifi_beacon", "timestamp": "2026-11-22T10:00:10+00:00", "bssid": "DE:AD:BE:EF:00:01",
    "ssid": "Campus-WiFi", "rssi": -90, "channel": 6, "encryption": "WPA2", "lat": 27.18, "lon": 31.18,
    "altitude": 30.0, "raw_payload": {"sim_ap": "rogue"},
}


def row(agent, mv, score=50, sev="medium"):
    return {"agent": agent, "model_version": mv, "severity": sev, "risk_score": score, "category": "rogue_ap",
            "confidence": 0.8, "explanation": "why", "recommended_action": "check", "features": {"a": 1},
            "processing_ms": 12, "error": None}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(config, "AI_CONTRACT_API_KEY", "ai-key-for-tests")
    Base.metadata.create_all(bind=engine)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_auth_required_and_key_checked(client, monkeypatch):
    assert client.post("/events", json=EVENT).status_code == 401
    assert client.post("/events", json=EVENT, headers={"X-API-Key": "wrong"}).status_code == 401
    # the existing Bearer token must NOT open the AI routes
    assert client.post("/events", json=EVENT, headers={"Authorization": "Bearer ai-token"}).status_code == 401
    monkeypatch.setattr(config, "AI_CONTRACT_API_KEY", "")
    assert client.post("/events", json=EVENT, headers=KEY).status_code == 500


def test_create_idempotent_and_get(client):
    r = client.post("/events", json=EVENT, headers=KEY)
    assert r.status_code == 201 and r.json()["status"] == "pending" and r.json()["bssid"] == EVENT["bssid"]
    again = client.post("/events", json={**EVENT, "rssi": -10}, headers=KEY)
    assert again.status_code == 200 and again.json()["rssi"] == -90
    assert len(client.get("/events", headers=KEY).json()) == 1
    assert client.get(f"/events/{EVENT['event_id']}", headers=KEY).json()["raw_payload"] == {"sim_ap": "rogue"}
    assert client.get("/events/nope", headers=KEY).status_code == 404


def test_event_id_generated_and_validation(client):
    e = {k: v for k, v in EVENT.items() if k != "event_id"}
    assert client.post("/events", json=e, headers=KEY).json()["event_id"]
    assert client.post("/events", json={**EVENT, "event_id": "x", "source": "bad"}, headers=KEY).status_code == 422
    assert client.post("/events", json={**EVENT, "event_id": "y", "encryption": "ROT13"}, headers=KEY).status_code == 422


def test_list_pending_oldest_first_and_limit(client):
    for i in range(3):
        client.post("/events", json={**EVENT, "event_id": f"e{i}"}, headers=KEY)
    ids = [e["event_id"] for e in client.get("/events?status=pending&limit=2", headers=KEY).json()]
    assert ids == ["e0", "e1"]
    assert client.get("/events?status=bogus", headers=KEY).status_code == 422


def test_claim_is_single_winner(client):
    client.post("/events", json=EVENT, headers=KEY)
    eid = EVENT["event_id"]
    first = client.post(f"/events/{eid}/claim", headers=KEY)
    assert first.status_code == 200 and first.json()["status"] == "processing"
    assert client.post(f"/events/{eid}/claim", headers=KEY).status_code == 409
    assert client.post("/events/missing/claim", headers=KEY).status_code == 404


def test_status_patch_and_requeue(client):
    client.post("/events", json=EVENT, headers=KEY)
    eid = EVENT["event_id"]
    assert client.patch(f"/events/{eid}/status", json={"status": "analyzed"}, headers=KEY).json()["status"] == "analyzed"
    assert client.patch(f"/events/{eid}/status", json={"status": "failed", "error": "boom"}, headers=KEY).json()["status_error"] == "boom"
    assert client.patch(f"/events/{eid}/status", json={"status": "acknowledged"}, headers=KEY).status_code == 422
    client.patch(f"/events/{eid}/status", json={"status": "pending"}, headers=KEY)
    client.post(f"/events/{eid}/claim", headers=KEY)
    assert client.post("/events/requeue-stuck", json={"older_than_seconds": 300}, headers=KEY).json() == {"requeued": 0}
    db = Session()
    db.execute(update(AIEvent).where(AIEvent.event_id == eid).values(claimed_at=datetime.now(timezone.utc) - timedelta(seconds=999)))
    db.commit()
    db.close()
    assert client.post("/events/requeue-stuck", json={"older_than_seconds": 300}, headers=KEY).json() == {"requeued": 1}
    assert client.get(f"/events/{eid}", headers=KEY).json()["status"] == "pending"
    assert client.post("/events/requeue-stuck", headers=KEY).status_code == 200  # body optional


def test_three_agents_are_all_kept_and_rerun_upserts(client):
    client.post("/events", json=EVENT, headers=KEY)
    eid = EVENT["event_id"]
    rows = [row("sentinel", "s1", 40), row("prediction", "p1", 60), row("risk", "r1", 85, "critical")]
    r = client.post("/analysis-results/bulk", json={"event_id": eid, "results": rows}, headers=KEY)
    assert r.status_code == 201 and r.json() == {"saved": 3}
    got = client.get(f"/events/{eid}/analysis-results", headers=KEY).json()
    assert {x["agent"] for x in got} == {"sentinel", "prediction", "risk"}
    # re-run: same key replaces, never duplicates, other agents untouched
    client.post("/analysis-results/bulk", json={"event_id": eid, "results": [row("risk", "r1", 90, "critical")]}, headers=KEY)
    got = client.get(f"/events/{eid}/analysis-results", headers=KEY).json()
    assert len(got) == 3 and [x for x in got if x["agent"] == "risk"][0]["risk_score"] == 90
    # a new model version is a new row
    client.post("/analysis-results/bulk", json={"event_id": eid, "results": [row("risk", "r2", 10, "low")]}, headers=KEY)
    assert len(client.get(f"/events/{eid}/analysis-results", headers=KEY).json()) == 4


def test_bulk_validation(client):
    client.post("/events", json=EVENT, headers=KEY)
    eid = EVENT["event_id"]
    assert client.post("/analysis-results/bulk", json={"event_id": "nope", "results": [row("risk", "r1")]}, headers=KEY).status_code == 404
    assert client.post("/analysis-results/bulk", json={"results": [row("risk", "r1")]}, headers=KEY).status_code == 422
    bad = {**row("risk", "r1"), "severity": "urgent"}
    assert client.post("/analysis-results/bulk", json={"event_id": eid, "results": [bad]}, headers=KEY).status_code == 422
    bad = {**row("risk", "r1"), "risk_score": 101}
    assert client.post("/analysis-results/bulk", json={"event_id": eid, "results": [bad]}, headers=KEY).status_code == 422
    assert client.post("/analysis-results/bulk", json={"event_id": eid, "results": []}, headers=KEY).status_code == 422
    assert client.get(f"/events/{eid}/analysis-results", headers=KEY).json() == []  # nothing half-saved


def test_missions_runs_alerts_reports(client):
    client.post("/events", json=EVENT, headers=KEY)
    eid = EVENT["event_id"]
    client.post("/analysis-results/bulk", json={"event_id": eid, "results": [row("sentinel", "s1"), row("risk", "r1", 85, "critical")]}, headers=KEY)
    assert client.get("/missions/mission-demo-001", headers=KEY).json() == {"mission_id": "mission-demo-001"}
    assert client.post("/missions", json={"mission_id": "mission-demo-001", "drone_id": "scar-01"}, headers=KEY).status_code == 201
    assert client.get("/missions/mission-demo-001", headers=KEY).json()["drone_id"] == "scar-01"
    assert len(client.get("/missions/mission-demo-001/events", headers=KEY).json()) == 1
    risk = client.get("/missions/mission-demo-001/analysis-results?agent=risk", headers=KEY).json()
    assert [x["agent"] for x in risk] == ["risk"]
    assert len(client.get("/missions/mission-demo-001/analysis-results", headers=KEY).json()) == 2
    assert client.post("/workflow-runs", json={"workflow_name": "W2", "event_id": eid, "status": "success", "attempts": 1, "extra": 1}, headers=KEY).status_code == 201
    assert client.post("/workflow-runs", json={"workflow_name": "W2", "status": "weird"}, headers=KEY).status_code == 422
    assert client.post("/alerts", json={"event_id": eid, "severity": "critical", "risk_score": 85, "category": "rogue_ap", "message": "m", "channel": "telegram", "delivery": "sent"}, headers=KEY).status_code == 201
    assert client.post("/reports", json={"mission_id": "mission-demo-001", "format": "markdown", "content": "# r"}, headers=KEY).status_code == 201


def test_existing_api_and_status_enums_unchanged(client):
    """The /api/v1 alert statuses stay new/investigating/resolved/false_positive; AI status is separate."""
    from app.schemas import EventStatus
    assert [s.value for s in EventStatus] == ["new", "investigating", "resolved", "false_positive"]
    assert client.get("/health").json() == {"status": "ok"}  # root /health unchanged, no key needed
    assert client.get("/api/v1/events").status_code == 200
    assert client.post("/api/v1/ai/analysis", json={}, headers={"Authorization": "Bearer ai-token"}).status_code == 422
    assert client.post("/api/v1/ai/analysis", json={}, headers=KEY).status_code == 401  # X-API-Key does not open it
    client.post("/events", json=EVENT, headers=KEY)
    assert client.get("/api/v1/events").json()["total"] == 0  # AI events are not mixed into security_events
