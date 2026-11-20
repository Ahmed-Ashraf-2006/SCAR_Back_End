import os

# must be set before the app is imported
os.environ["API_TOKEN"] = "test-token"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app

engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

URL = "/api/v1/telemetry"
AUTH = {"Authorization": "Bearer test-token"}


def good_packet(sequence=1):
    return {
        "drone_id": "SCAR-DRONE-001",
        "timestamp": "2026-11-19T17:00:00Z",
        "sequence": sequence,
        "telemetry": {
            "altitude_m": 10.5,
            "speed_mps": 2.4,
            "roll_deg": 1.2,
            "pitch_deg": -0.8,
            "yaw_deg": 90.0,
            "battery_voltage": 11.7,
            "battery_percentage": 78,
            "flight_mode": "STABILIZE",
            "gps": {"latitude": 27.1809, "longitude": 31.1837, "satellites": 9},
        },
    }


@pytest.fixture()
def client():
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


# ---------------- health ----------------
def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


# ---------------- telemetry: success ----------------
def test_valid_packet_accepted(client):
    r = client.post(URL, json=good_packet(), headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"status": "accepted", "drone_id": "SCAR-DRONE-001", "sequence": 1}


def test_unavailable_fields_stay_null(client):
    packet = {
        "drone_id": "SCAR-DRONE-001",
        "timestamp": "2026-11-19T17:00:00Z",
        "sequence": 1,
        "telemetry": {"altitude_m": None, "gps": None},
    }
    assert client.post(URL, json=packet, headers=AUTH).status_code == 200
    saved = client.get(f"{URL}/SCAR-DRONE-001/latest", headers=AUTH).json()
    assert saved["telemetry"]["altitude_m"] is None
    assert saved["telemetry"]["speed_mps"] is None
    assert saved["telemetry"]["gps"] is None


def test_get_latest(client):
    client.post(URL, json=good_packet(1), headers=AUTH)
    client.post(URL, json=good_packet(2), headers=AUTH)
    r = client.get(f"{URL}/SCAR-DRONE-001/latest", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["sequence"] == 2
    assert r.json()["telemetry"]["gps"]["satellites"] == 9


def test_latest_not_found(client):
    assert client.get(f"{URL}/nope/latest", headers=AUTH).status_code == 404


# ---------------- telemetry: authentication ----------------
def test_missing_token_rejected(client):
    assert client.post(URL, json=good_packet()).status_code == 401


def test_wrong_token_rejected(client):
    r = client.post(URL, json=good_packet(), headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


# ---------------- telemetry: validation ----------------
def test_missing_drone_id_rejected(client):
    p = good_packet()
    del p["drone_id"]
    assert client.post(URL, json=p, headers=AUTH).status_code == 422


def test_missing_telemetry_object_rejected(client):
    p = good_packet()
    del p["telemetry"]
    assert client.post(URL, json=p, headers=AUTH).status_code == 422


def test_invalid_gps_latitude_rejected(client):
    p = good_packet()
    p["telemetry"]["gps"]["latitude"] = 95
    assert client.post(URL, json=p, headers=AUTH).status_code == 422


def test_latitude_without_longitude_rejected(client):
    p = good_packet()
    p["telemetry"]["gps"] = {"latitude": 27.1, "longitude": None, "satellites": 5}
    assert client.post(URL, json=p, headers=AUTH).status_code == 422


def test_invalid_battery_rejected(client):
    p = good_packet()
    p["telemetry"]["battery_percentage"] = 150
    assert client.post(URL, json=p, headers=AUTH).status_code == 422


# ---------------- telemetry: duplicates and DB failure ----------------
def test_duplicate_sequence_rejected(client):
    assert client.post(URL, json=good_packet(5), headers=AUTH).status_code == 200
    assert client.post(URL, json=good_packet(5), headers=AUTH).status_code == 409


def test_database_failure_returns_500(client):
    class BrokenSession:
        def query(self, *args, **kwargs):
            raise OperationalError("SELECT", {}, Exception("db down"))

        def rollback(self):
            pass

        def close(self):
            pass

    app.dependency_overrides[get_db] = lambda: BrokenSession()
    assert client.post(URL, json=good_packet(), headers=AUTH).status_code == 500


# ---------------- security events (unchanged) ----------------
def test_event_lifecycle(client):
    ev = {"source": "ids", "event_type": "port_scan", "severity": "high", "device_ip": "192.168.1.20"}
    r = client.post("/events/", json=ev)
    assert r.status_code == 201
    eid = r.json()["id"]
    assert client.patch(f"/events/{eid}/status", json={"status": "resolved"}).json()["status"] == "resolved"
    assert len(client.get("/events/?severity=high").json()) == 1
    assert client.delete(f"/events/{eid}").status_code == 204
    assert client.get(f"/events/{eid}").status_code == 404


def test_invalid_severity(client):
    ev = {"source": "ids", "event_type": "x", "severity": "huge"}
    assert client.post("/events/", json=ev).status_code == 422


def test_invalid_ip_rejected(client):
    ev = {"source": "ids", "event_type": "x", "severity": "low", "device_ip": "abc"}
    assert client.post("/events/", json=ev).status_code == 422
