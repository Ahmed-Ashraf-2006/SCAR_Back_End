import os

# must be set before the app is imported
os.environ["API_TOKEN"] = "test-token"
os.environ["SECURITY_TOKEN"] = "sec-token"
os.environ["AI_TOKEN"] = "ai-token"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import config
from app.database import Base, get_db
from app.main import app
from app.models import Drone
from app.security import hash_token

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

URL = "/api/v1/telemetry"
EV = "/api/v1/events"
AL = "/api/v1/alerts"
AI = "/api/v1/ai/analysis"

DASH = {"Authorization": "Bearer test-token"}   # dashboard / administrator
SEC = {"Authorization": "Bearer sec-token"}     # security team
AIH = {"Authorization": "Bearer ai-token"}      # AI automation
DRONE = {"Authorization": "Bearer drone-token-1"}
OTHER_DRONE = {"Authorization": "Bearer drone-token-2"}


def register_drone(drone_id, token, active=True):
    db = TestingSession()
    db.add(Drone(drone_id=drone_id, token_hash=hash_token(token), active=active))
    db.commit()
    db.close()


def good_packet(sequence=1, **over):
    p = {
        "drone_id": "SCAR-DRONE-001",
        "schema_version": "1.0",
        "boot_id": "boot-a",
        "timestamp": "2026-11-19T17:00:00Z",
        "sequence": sequence,
        "telemetry": {
            "altitude_m": 10.5, "speed_mps": 2.4,
            "roll_deg": 1.2, "pitch_deg": -0.8, "yaw_deg": 90.0,
            "battery_voltage": 11.7, "battery_percentage": 78,
            "flight_mode": "STABILIZE", "system_status": "ok",
            "gps": {"latitude": 27.1809, "longitude": 31.1837, "satellites": 9},
        },
    }
    p.update(over)
    return p


def good_health(sequence=1, **over):
    p = {
        "drone_id": "SCAR-DRONE-001", "schema_version": "1.0", "boot_id": "boot-a",
        "timestamp": "2026-11-19T17:00:05Z", "sequence": sequence,
        "health": {"overall_status": "ok", "cpu_percent": 41.5, "memory_percent": 60.0,
                   "cpu_temp_c": 55.2, "storage_percent": 33.0, "link_rssi_dbm": -62,
                   "uptime_s": 1200, "components": {"gps": "ok", "camera": "degraded"}},
    }
    p.update(over)
    return p


def good_drone_event(sequence=1, **over):
    p = {
        "drone_id": "SCAR-DRONE-001", "schema_version": "1.0", "boot_id": "boot-a",
        "timestamp": "2026-11-19T17:01:00Z", "sequence": sequence,
        "event_uid": f"evt-{sequence}", "event_type": "rogue_ap_detected",
        "severity_label": "high", "description": "Unknown access point near the drone",
        "raw": {"ssid": "free-wifi"},
    }
    p.update(over)
    return p


@pytest.fixture()
def client():
    Base.metadata.create_all(bind=engine)
    register_drone("SCAR-DRONE-001", "drone-token-1")
    register_drone("SCAR-DRONE-002", "drone-token-2")

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


# ================= health =================
def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


# ================= telemetry: success =================
def test_valid_packet_accepted(client):
    r = client.post(URL, json=good_packet(), headers=DRONE)
    assert r.status_code == 200
    assert r.json() == {"status": "accepted", "drone_id": "SCAR-DRONE-001", "sequence": 1, "gap": None}


def test_unavailable_fields_stay_null(client):
    packet = {"drone_id": "SCAR-DRONE-001", "timestamp": "2026-11-19T17:00:00Z", "sequence": 1,
              "telemetry": {"altitude_m": None, "gps": None}}
    assert client.post(URL, json=packet, headers=DRONE).status_code == 200
    saved = client.get(f"{URL}/SCAR-DRONE-001/latest", headers=DASH).json()
    assert saved["telemetry"]["altitude_m"] is None
    assert saved["telemetry"]["speed_mps"] is None
    assert saved["telemetry"]["gps"] is None


def test_get_latest_and_new_fields_roundtrip(client):
    client.post(URL, json=good_packet(1), headers=DRONE)
    client.post(URL, json=good_packet(2), headers=DRONE)
    body = client.get(f"{URL}/SCAR-DRONE-001/latest", headers=DASH).json()
    assert body["sequence"] == 2
    assert body["schema_version"] == "1.0" and body["boot_id"] == "boot-a"
    assert body["telemetry"]["system_status"] == "ok"
    assert body["telemetry"]["gps"]["satellites"] == 9


def test_schema_version_and_boot_id_are_optional_with_defaults(client):
    p = good_packet()
    del p["schema_version"], p["boot_id"]
    assert client.post(URL, json=p, headers=DRONE).status_code == 200
    body = client.get(f"{URL}/SCAR-DRONE-001/latest", headers=DASH).json()
    assert body["schema_version"] == "1.0" and body["boot_id"] == "0"


def test_timestamps_returned_as_utc(client):
    client.post(URL, json=good_packet(), headers=DRONE)
    body = client.get(f"{URL}/SCAR-DRONE-001/latest", headers=DASH).json()
    assert body["timestamp"] == "2026-11-19T17:00:00Z"
    assert body["received_at"].endswith("Z")


def test_latest_not_found(client):
    assert client.get(f"{URL}/nope/latest", headers=DASH).status_code == 404


# ================= telemetry: authentication =================
def test_missing_token_rejected(client):
    assert client.post(URL, json=good_packet()).status_code == 401


def test_wrong_token_rejected(client):
    assert client.post(URL, json=good_packet(), headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_dashboard_token_cannot_write_telemetry(client):
    assert client.post(URL, json=good_packet(), headers=DASH).status_code == 401


def test_revoked_drone_token_rejected(client):
    db = TestingSession()
    db.query(Drone).filter(Drone.drone_id == "SCAR-DRONE-001").update({"active": False})
    db.commit()
    db.close()
    assert client.post(URL, json=good_packet(), headers=DRONE).status_code == 401


def test_drone_token_cannot_write_for_another_drone(client):
    r = client.post(URL, json=good_packet(drone_id="SCAR-DRONE-002"), headers=DRONE)
    assert r.status_code == 403
    assert client.post(URL, json=good_packet(drone_id="SCAR-DRONE-002"), headers=OTHER_DRONE).status_code == 200


def test_drone_token_cannot_read_dashboard_routes(client):
    assert client.get(URL, headers=DRONE).status_code == 401
    assert client.get("/api/v1/drones", headers=DRONE).status_code == 401


def test_unconfigured_server_token_is_a_server_error(client, monkeypatch):
    monkeypatch.setattr(config, "API_TOKEN", "")
    assert client.get(URL, headers=DASH).status_code == 500


# ================= telemetry: validation =================
def test_missing_drone_id_rejected(client):
    p = good_packet()
    del p["drone_id"]
    assert client.post(URL, json=p, headers=DRONE).status_code == 422


def test_missing_telemetry_object_rejected(client):
    p = good_packet()
    del p["telemetry"]
    assert client.post(URL, json=p, headers=DRONE).status_code == 422


def test_invalid_gps_latitude_rejected(client):
    p = good_packet()
    p["telemetry"]["gps"]["latitude"] = 95
    assert client.post(URL, json=p, headers=DRONE).status_code == 422


def test_latitude_without_longitude_rejected(client):
    p = good_packet()
    p["telemetry"]["gps"] = {"latitude": 27.1, "longitude": None, "satellites": 5}
    assert client.post(URL, json=p, headers=DRONE).status_code == 422


def test_invalid_battery_rejected(client):
    p = good_packet()
    p["telemetry"]["battery_percentage"] = 150
    assert client.post(URL, json=p, headers=DRONE).status_code == 422


@pytest.mark.parametrize("version,ok", [("1.0", True), ("1.7", True), ("2.0", False), ("1", False), ("v1.0", False)])
def test_schema_version_rules(client, version, ok):
    r = client.post(URL, json=good_packet(schema_version=version), headers=DRONE)
    assert (r.status_code == 200) is ok
    if not ok:
        assert r.status_code == 422


def test_invalid_boot_id_rejected(client):
    assert client.post(URL, json=good_packet(boot_id="bad id!"), headers=DRONE).status_code == 422


# ================= telemetry: duplicates, reboot, gaps =================
def test_duplicate_sequence_rejected(client):
    assert client.post(URL, json=good_packet(5), headers=DRONE).status_code == 200
    assert client.post(URL, json=good_packet(5), headers=DRONE).status_code == 409


def test_reboot_may_restart_sequence_with_new_boot_id(client):
    assert client.post(URL, json=good_packet(1, boot_id="boot-a"), headers=DRONE).status_code == 200
    assert client.post(URL, json=good_packet(1, boot_id="boot-b"), headers=DRONE).status_code == 200
    assert client.post(URL, json=good_packet(1, boot_id="boot-b"), headers=DRONE).status_code == 409


def test_gap_is_reported(client):
    assert client.post(URL, json=good_packet(1), headers=DRONE).json()["gap"] is None
    assert client.post(URL, json=good_packet(2), headers=DRONE).json()["gap"] is None
    gap = client.post(URL, json=good_packet(6), headers=DRONE).json()["gap"]
    assert gap == {"expected_sequence": 3, "received_sequence": 6, "missing": 3}


def test_out_of_order_packet_is_not_a_gap(client):
    client.post(URL, json=good_packet(1), headers=DRONE)
    client.post(URL, json=good_packet(4), headers=DRONE)
    assert client.post(URL, json=good_packet(3), headers=DRONE).json()["gap"] is None


def test_gap_is_per_boot(client):
    client.post(URL, json=good_packet(10, boot_id="boot-a"), headers=DRONE)
    assert client.post(URL, json=good_packet(0, boot_id="boot-b"), headers=DRONE).json()["gap"] is None


def test_database_failure_returns_500(client, monkeypatch):
    from app.services import telemetry_service

    def boom(*args, **kwargs):
        raise OperationalError("INSERT", {}, Exception("db down"))

    monkeypatch.setattr(telemetry_service, "create_telemetry", boom)
    assert client.post(URL, json=good_packet(), headers=DRONE).status_code == 500


# ================= system health =================
def test_health_message_accepted_and_readable(client):
    r = client.post("/api/v1/health", json=good_health(), headers=DRONE)
    assert r.status_code == 200 and r.json()["gap"] is None
    body = client.get("/api/v1/drones/SCAR-DRONE-001/health/latest", headers=DASH).json()
    assert body["health"]["cpu_percent"] == 41.5
    assert body["health"]["components"] == {"gps": "ok", "camera": "degraded"}
    assert body["timestamp"].endswith("Z")


def test_health_rules(client):
    assert client.post("/api/v1/health", json=good_health()).status_code == 401
    assert client.post("/api/v1/health", json=good_health(drone_id="SCAR-DRONE-002"), headers=DRONE).status_code == 403
    bad = good_health()
    bad["health"]["cpu_percent"] = 140
    assert client.post("/api/v1/health", json=bad, headers=DRONE).status_code == 422
    assert client.post("/api/v1/health", json=good_health(1), headers=DRONE).status_code == 200
    assert client.post("/api/v1/health", json=good_health(1), headers=DRONE).status_code == 409
    gap = client.post("/api/v1/health", json=good_health(4), headers=DRONE).json()["gap"]
    assert gap["missing"] == 2
    assert client.get("/api/v1/drones/nope/health/latest", headers=DASH).status_code == 404
    assert client.get("/api/v1/drones/SCAR-DRONE-001/health/latest").status_code == 401


def test_health_has_its_own_sequence_counter(client):
    client.post(URL, json=good_packet(1), headers=DRONE)
    client.post(URL, json=good_packet(2), headers=DRONE)
    assert client.post("/api/v1/health", json=good_health(1), headers=DRONE).status_code == 200


# ================= drone events =================
def test_drone_event_is_stored_as_security_event(client):
    r = client.post("/api/v1/drone-events", json=good_drone_event(), headers=DRONE)
    assert r.status_code == 201
    eid = r.json()["event_id"]
    body = client.get(f"{EV}/{eid}").json()
    assert body["source"] == "drone" and body["severity_label"] == "high"
    assert body["severity"] is None and body["status"] == "new"
    assert body["source_alert_id"] == "evt-1" and body["raw"] == {"ssid": "free-wifi"}


def test_drone_event_rules(client):
    url = "/api/v1/drone-events"
    assert client.post(url, json=good_drone_event()).status_code == 401
    assert client.post(url, json=good_drone_event(), headers=SEC).status_code == 401
    assert client.post(url, json=good_drone_event(drone_id="SCAR-DRONE-002"), headers=DRONE).status_code == 403
    assert client.post(url, json=good_drone_event(1), headers=DRONE).status_code == 201
    assert client.post(url, json=good_drone_event(1, event_uid="other"), headers=DRONE).status_code == 409  # same sequence
    assert client.post(url, json=good_drone_event(2, event_uid="evt-1"), headers=DRONE).status_code == 409   # retry, same uid
    gap = client.post(url, json=good_drone_event(5), headers=DRONE).json()["gap"]
    assert gap == {"expected_sequence": 2, "received_sequence": 5, "missing": 3}
    assert client.post(url, json=good_drone_event(6, severity_label="urgent"), headers=DRONE).status_code == 422


# ================= helpers for events / alerts =================
def unified_event(**over):
    base = {"source": "zeek", "event_type": "port_scan", "severity_label": "high", "description": "scan"}
    base.update(over)
    return base


WAZUH_RAW = {
    "id": "1700000000.1234",
    "timestamp": "2026-11-20T09:00:00.000+0000",
    "rule": {"id": "5712", "level": 10, "description": "sshd: brute force attack", "groups": ["authentication_failures"]},
    "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.10"},
    "data": {"srcip": "203.0.113.7"},
}
ZEEK_NOTICE_RAW = {"ts": 1795168800.5, "uid": "CAbc123", "note": "Scan::Port_Scan",
                   "msg": "10.0.0.5 scanned 20 ports", "src": "10.0.0.5", "dst": "10.0.0.10"}
ZEEK_CONN_RAW = {"ts": 1795168800.0, "uid": "CDef456", "id.orig_h": "10.0.0.5", "id.orig_p": 5555,
                 "id.resp_h": "10.0.0.10", "id.resp_p": 443, "proto": "tcp"}


def webhook(**over):
    p = {"alert_id": "1700000000.1234", "timestamp": "2026-11-20T09:00:00Z", "source": "wazuh",
         "rule_id": "5712", "rule_description": "sshd: brute force attack", "severity": 10,
         "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.10"},
         "src_ip": "203.0.113.7", "dst_ip": None, "sensor_ip": None, "status": "new",
         "raw": {"id": "1700000000.1234", "rule": {"id": "5712", "level": 10}}}
    p.update(over)
    return p


# ================= security events =================
def test_event_lifecycle_and_auth(client):
    assert client.post(EV, json=unified_event()).status_code == 401
    assert client.post(EV, json=unified_event(), headers=DASH).status_code == 401  # dashboard token is not the security token
    r = client.post(EV, json=unified_event(), headers=SEC)
    assert r.status_code == 201
    eid = r.json()["event_id"]
    assert client.patch(f"{EV}/{eid}/status", json={"status": "resolved"}).status_code == 401
    assert client.patch(f"{EV}/{eid}/status", json={"status": "resolved"}, headers=DASH).json()["status"] == "resolved"
    assert client.get(f"{EV}?severity_label=high").json()["total"] == 1
    assert client.delete(f"{EV}/{eid}").status_code == 401
    assert client.delete(f"{EV}/{eid}", headers=DASH).status_code == 204
    assert client.get(f"{EV}/{eid}").status_code == 404


def test_old_status_names_are_rejected(client):
    eid = client.post(EV, json=unified_event(), headers=SEC).json()["event_id"]
    for old in ("open", "acknowledged"):
        assert client.patch(f"{EV}/{eid}/status", json={"status": old}, headers=DASH).status_code == 422


def test_invalid_severity(client):
    assert client.post(EV, json=unified_event(severity_label="urgent"), headers=SEC).status_code == 422


def test_invalid_ip_rejected(client):
    assert client.post(EV, json=unified_event(device_ip="not-an-ip"), headers=SEC).status_code == 422
    assert client.post(EV, json=unified_event(source_ip="nope"), headers=SEC).status_code == 422
    assert client.post(EV, json=unified_event(destination_ip="999.1.1.1"), headers=SEC).status_code == 422


def test_event_full_fields_roundtrip(client):
    ev = unified_event(device_ip="192.168.1.20", source_ip="10.0.0.5", destination_ip="192.168.1.20",
                       rule_id="R-1001", source_alert_id="C1a2b3", title="Port scan", severity_value=11,
                       sensor_ip="10.9.9.9", raw_event={"uid": "C1a2b3", "proto": "tcp"})
    r = client.post(EV, json=ev, headers=SEC)
    assert r.status_code == 201
    body = client.get(f"{EV}/{r.json()['event_id']}").json()
    assert body["src_ip"] == "10.0.0.5" and body["dst_ip"] == "192.168.1.20"
    assert body["sensor_ip"] == "10.9.9.9"
    assert body["rule_id"] == "R-1001" and body["alert_id"] == "C1a2b3"
    assert body["severity"] == 11 and body["severity_label"] == "high"
    assert body["raw"] == {"uid": "C1a2b3", "proto": "tcp"}
    assert body["status"] == "new" and body["timestamp"].endswith("Z")
    assert body["ai_severity_label"] is None and body["risk_score"] is None


def test_event_optional_fields_default_null_and_title_falls_back(client):
    r = client.post(EV, json={"source": "wazuh", "event_type": "x", "severity_label": "low"}, headers=SEC)
    body = r.json()
    assert body["src_ip"] is None and body["dst_ip"] is None and body["sensor_ip"] is None
    assert body["rule_id"] is None and body["raw"] is None and body["agent"] is None
    assert body["title"] == "x"


def test_source_is_lowercased_and_new_source_needs_no_db_change(client):
    assert client.post(EV, json=unified_event(source="Zeek"), headers=SEC).json()["source"] == "zeek"
    assert client.post(EV, json=unified_event(source="suricata"), headers=SEC).status_code == 201
    assert client.get(f"{EV}?source=suricata").json()["total"] == 1


# ================= lists =================
def test_list_shape_paging_and_order(client):
    for minute in range(5):
        client.post(EV, json=unified_event(timestamp=f"2026-11-20T10:0{minute}:00Z", description=f"e{minute}"), headers=SEC)
    page = client.get(f"{EV}?limit=2&offset=1").json()
    assert set(page) == {"items", "total"}
    assert page["total"] == 5
    assert [e["rule_description"] for e in page["items"]] == ["e3", "e2"]
    assert "raw" not in page["items"][0]


def test_list_filters(client):
    client.post(EV, json=unified_event(source="zeek", severity_label="low", timestamp="2026-11-20T08:00:00Z"), headers=SEC)
    client.post(EV, json=unified_event(source="wazuh", severity_label="high", timestamp="2026-11-20T10:00:00Z"), headers=SEC)
    client.post(EV, json=unified_event(source="wazuh", severity_label="critical", timestamp="2026-11-20T12:00:00Z"), headers=SEC)
    assert client.get(f"{EV}?source=wazuh").json()["total"] == 2
    assert client.get(f"{EV}?severity_label=critical").json()["total"] == 1
    assert client.get(f"{EV}?from=2026-11-20T09:00:00Z&to=2026-11-20T11:00:00Z").json()["total"] == 1
    assert client.get(f"{EV}?status=resolved").json()["total"] == 0
    assert client.get(f"{EV}?severity_label=bogus").status_code == 422


def test_error_format_has_detail(client):
    r = client.get(f"{EV}/9999")
    assert r.status_code == 404 and r.json() == {"detail": "Event not found"}


# ================= raw ingest + normalization =================
def test_ingest_requires_security_token(client):
    assert client.post("/api/v1/ingest/wazuh", json=WAZUH_RAW).status_code == 401
    assert client.post("/api/v1/ingest/wazuh", json=WAZUH_RAW, headers=DASH).status_code == 401
    assert client.post("/api/v1/ingest/wazuh", json=WAZUH_RAW, headers=AIH).status_code == 401


def test_ingest_wazuh_is_normalized_and_raw_kept(client):
    r = client.post("/api/v1/ingest/wazuh", json=WAZUH_RAW, headers=SEC)
    assert r.status_code == 201 and r.json()["ingested"] == 1
    body = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    assert body["source"] == "wazuh" and body["alert_id"] == "1700000000.1234"
    assert body["event_id"] != body["alert_id"]
    assert body["severity"] == 10 and body["severity_label"] == "high"
    assert body["rule_id"] == "5712"
    assert body["agent"] == {"id": "001", "name": "web-01", "ip": "10.0.0.10"}
    assert body["src_ip"] == "203.0.113.7" and body["sensor_ip"] is None
    assert body["title"] == "sshd: brute force attack"
    assert body["timestamp"] == "2026-11-20T09:00:00Z"
    assert body["raw"] == WAZUH_RAW


def test_wazuh_level_mapping():
    from app.normalizers import wazuh_severity
    assert [wazuh_severity(n) for n in (0, 6, 7, 9, 10, 12, 13, 15)] == [
        "low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_ingest_zeek_notice_and_connection_is_skipped(client):
    r = client.post("/api/v1/ingest/zeek", json=[ZEEK_NOTICE_RAW, ZEEK_CONN_RAW], headers=SEC)
    assert r.status_code == 201 and r.json()["ingested"] == 1
    notice = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    assert notice["event_type"] == "Scan::Port_Scan" and notice["severity_label"] == "medium"
    assert notice["severity"] is None  # no invented Wazuh level
    assert notice["src_ip"] == "10.0.0.5" and notice["dst_ip"] == "10.0.0.10"
    assert notice["alert_id"] == "CAbc123" and notice["raw"] == ZEEK_NOTICE_RAW
    only_conn = client.post("/api/v1/ingest/zeek", json=ZEEK_CONN_RAW, headers=SEC)
    assert only_conn.status_code == 201 and only_conn.json()["ingested"] == 0
    assert client.get(EV).json()["total"] == 1


def test_zeek_sensor_ip_comes_from_raw_or_deployment_setting(client, monkeypatch):
    from app import normalizers
    r = client.post("/api/v1/ingest/zeek", json={**ZEEK_NOTICE_RAW, "sensor_ip": "10.1.1.1"}, headers=SEC)
    assert client.get(f"{EV}/{r.json()['ids'][0]}").json()["sensor_ip"] == "10.1.1.1"
    monkeypatch.setattr(normalizers, "SENSOR_IP", "10.2.2.2")
    r = client.post("/api/v1/ingest/zeek", json=ZEEK_NOTICE_RAW, headers=SEC)
    body = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    assert body["sensor_ip"] == "10.2.2.2" and body["src_ip"] == "10.0.0.5"  # never taken from the endpoints


def test_ingest_zeek_nested_id_format(client):
    raw = {"ts": 1795168800.0, "uid": "CN1", "note": "SSL::Invalid_Server_Cert", "id": {"orig_h": "10.0.0.7", "resp_h": "10.0.0.8"}}
    r = client.post("/api/v1/ingest/zeek", json=raw, headers=SEC)
    body = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    assert body["src_ip"] == "10.0.0.7" and body["dst_ip"] == "10.0.0.8"


def test_ingest_unknown_source(client):
    r = client.post("/api/v1/ingest/nope", json={}, headers=SEC)
    assert r.status_code == 404 and "wazuh" in r.json()["detail"]


def test_ingest_invalid_event_saves_nothing(client):
    r = client.post("/api/v1/ingest/wazuh", json=[WAZUH_RAW, {"rule": {}}], headers=SEC)
    assert r.status_code == 422 and "Event #1" in r.json()["detail"]
    assert client.get(EV).json()["total"] == 0


def test_ingest_empty_and_unrecognised_zeek(client):
    assert client.post("/api/v1/ingest/zeek", json=[], headers=SEC).status_code == 422
    assert client.post("/api/v1/ingest/zeek", json={"foo": "bar"}, headers=SEC).status_code == 422


# ================= alert webhook =================
def test_alert_webhook_wazuh(client):
    assert client.post(AL, json=webhook()).status_code == 401
    assert client.post(AL, json=webhook(), headers=DASH).status_code == 401
    r = client.post(AL, json=webhook(), headers=SEC)
    assert r.status_code == 201
    body = r.json()
    assert body["event_id"] > 0 and body["alert_id"] == "1700000000.1234"
    assert body["severity"] == 10 and body["severity_label"] == "high"
    assert body["agent"]["ip"] == "10.0.0.10" and body["sensor_ip"] is None
    assert body["status"] == "new" and body["raw"]["rule"]["level"] == 10


@pytest.mark.parametrize("level,label", [(0, "low"), (6, "low"), (7, "medium"), (9, "medium"), (10, "high"), (12, "high"), (13, "critical"), (15, "critical")])
def test_alert_webhook_severity_ranges(client, level, label):
    r = client.post(AL, json=webhook(severity=level), headers=SEC)
    assert r.json()["severity_label"] == label


def test_alert_webhook_severity_rules(client):
    assert client.post(AL, json=webhook(severity=10, severity_label="high"), headers=SEC).status_code == 201
    assert client.post(AL, json=webhook(severity=10, severity_label="low"), headers=SEC).status_code == 422
    assert client.post(AL, json=webhook(severity=16), headers=SEC).status_code == 422
    assert client.post(AL, json=webhook(severity=None), headers=SEC).status_code == 422  # Wazuh needs the number
    p = webhook(severity=None)
    del p["severity"]
    assert client.post(AL, json=p, headers=SEC).status_code == 422


def test_alert_webhook_zeek_label_only_and_sensor_ip(client, monkeypatch):
    from app.services import event_service
    monkeypatch.setattr(event_service, "SENSOR_IP", "10.5.5.5")
    p = webhook(source="zeek", severity=None, severity_label="medium", agent=None, src_ip="10.0.0.5", dst_ip="10.0.0.10")
    body = client.post(AL, json=p, headers=SEC).json()
    assert body["severity"] is None and body["severity_label"] == "medium"
    assert body["agent"] is None and body["sensor_ip"] == "10.5.5.5"
    assert body["src_ip"] == "10.0.0.5"
    given = client.post(AL, json={**p, "alert_id": "z2", "sensor_ip": "10.6.6.6"}, headers=SEC).json()
    assert given["sensor_ip"] == "10.6.6.6"


def test_alert_webhook_wazuh_sensor_ip_is_not_guessed(client, monkeypatch):
    from app.services import event_service
    monkeypatch.setattr(event_service, "SENSOR_IP", "10.5.5.5")
    assert client.post(AL, json=webhook(), headers=SEC).json()["sensor_ip"] is None


def test_alert_webhook_validation(client):
    assert client.post(AL, json=webhook(status="open"), headers=SEC).status_code == 422
    assert client.post(AL, json=webhook(source="suricata"), headers=SEC).status_code == 422
    assert client.post(AL, json=webhook(src_ip="nope"), headers=SEC).status_code == 422
    assert client.post(AL, json=webhook(sensor_ip="999.9.9.9"), headers=SEC).status_code == 422
    assert client.post(AL, json=webhook(agent={"ip": "bad"}), headers=SEC).status_code == 422
    p = webhook()
    del p["raw"]
    assert client.post(AL, json=p, headers=SEC).status_code == 422


# ================= alerts (dashboard shape) =================
def test_alerts_list_shape_and_status_change(client):
    eid = client.post(EV, json=unified_event(title="Port scan detected", source_alert_id="C9", severity_value=8), headers=SEC).json()["event_id"]
    page = client.get(AL).json()
    assert page["total"] == 1
    alert = page["items"][0]
    assert {"id", "event_id", "alert_id", "title", "severity", "severity_label", "source", "status",
            "timestamp", "description", "agent", "sensor_ip", "src_ip", "dst_ip", "ai_severity_label", "risk_score"} <= set(alert)
    assert alert["title"] == "Port scan detected" and alert["severity"] == 8 and alert["severity_label"] == "high"
    assert client.patch(f"{AL}/{eid}/status", json={"status": "investigating"}).status_code == 401
    assert client.patch(f"{AL}/{eid}/status", json={"status": "investigating"}, headers=DASH).json()["status"] == "investigating"
    assert client.get(f"{AL}?status=investigating").json()["total"] == 1
    assert client.get(f"{AL}/{eid}").json()["event_id"] == eid
    assert client.get(f"{AL}/9999").status_code == 404


# ================= AI analysis =================
def ai_payload(event_id, **over):
    p = {"event_id": event_id, "agent_name": "scar-ai-agent", "model_version": "1.0.0", "severity": "critical",
         "risk_score": 82.5, "category": "credential_attack", "confidence": 0.94,
         "explanation": "Repeated failed logins.", "recommended_action": "Block the source IP.",
         "created_at": "2026-11-23T10:30:00Z"}
    p.update(over)
    return p


def test_ai_analysis_attaches_to_event_and_keeps_source_severity(client):
    eid = client.post(AL, json=webhook(), headers=SEC).json()["event_id"]
    assert client.post(AI, json=ai_payload(eid)).status_code == 401
    assert client.post(AI, json=ai_payload(eid), headers=DASH).status_code == 401  # internal token only
    assert client.post(AI, json=ai_payload(eid), headers=SEC).status_code == 401
    r = client.post(AI, json=ai_payload(eid), headers=AIH)
    assert r.status_code == 200
    body = client.get(f"{EV}/{eid}").json()
    assert body["ai_severity_label"] == "critical"
    assert body["severity"] == 10 and body["severity_label"] == "high"  # source severity untouched
    assert body["risk_score"] == 82.5 and body["confidence"] == 0.94
    assert body["agent_name"] == "scar-ai-agent" and body["category"] == "credential_attack"
    assert body["created_at"] == "2026-11-23T10:30:00Z"
    assert client.get(AL).json()["items"][0]["risk_score"] == 82.5


def test_ai_analysis_replaces_the_latest_result(client):
    eid = client.post(AL, json=webhook(), headers=SEC).json()["event_id"]
    client.post(AI, json=ai_payload(eid), headers=AIH)
    client.post(AI, json=ai_payload(eid, risk_score=10, severity="low"), headers=AIH)
    body = client.get(f"{EV}/{eid}").json()
    assert body["risk_score"] == 10 and body["ai_severity_label"] == "low"


def test_ai_analysis_validation(client):
    eid = client.post(AL, json=webhook(), headers=SEC).json()["event_id"]
    assert client.post(AI, json=ai_payload(9999), headers=AIH).status_code == 404
    assert client.post(AI, json=ai_payload(eid, risk_score=101), headers=AIH).status_code == 422
    assert client.post(AI, json=ai_payload(eid, risk_score=-1), headers=AIH).status_code == 422
    assert client.post(AI, json=ai_payload(eid, severity="urgent"), headers=AIH).status_code == 422
    assert client.post(AI, json=ai_payload(eid, agent_name="  "), headers=AIH).status_code == 422
    p = ai_payload(eid)
    del p["created_at"]
    assert client.post(AI, json=p, headers=AIH).status_code == 200
    assert client.get(f"{EV}/{eid}").json()["created_at"].endswith("Z")


# ================= overview =================
def test_overview_counts(client):
    client.post(EV, json=unified_event(severity_label="high"), headers=SEC)
    client.post(EV, json=unified_event(severity_label="high"), headers=SEC)
    done = client.post(EV, json=unified_event(severity_label="low"), headers=SEC).json()["event_id"]
    client.patch(f"{EV}/{done}/status", json={"status": "resolved"}, headers=DASH)
    client.post(URL, json=good_packet(), headers=DRONE)
    body = client.get("/api/v1/overview").json()
    assert body["alerts"]["total"] == 3
    assert body["alerts"]["by_severity"] == {"low": 1, "medium": 0, "high": 2, "critical": 0}
    assert body["alerts"]["by_status"] == {"new": 2, "investigating": 0, "resolved": 1}
    assert body["alerts"]["new_by_severity"]["low"] == 0 and body["alerts"]["new_by_severity"]["high"] == 2
    assert body["drones"] == {"total": 1, "online": 1, "offline": 0}
    assert body["risk"] == {"score": None, "level": None, "updated_at": None}


# ================= drones =================
def test_drones_latest_and_online_status(client):
    client.post(URL, json=good_packet(1), headers=DRONE)
    page = client.get("/api/v1/drones", headers=DASH).json()
    assert page["total"] == 1
    d = page["items"][0]
    assert d["drone_id"] == "SCAR-DRONE-001" and d["status"] == "online"
    assert d["latitude"] == 27.1809 and d["longitude"] == 31.1837
    assert d["altitude_m"] == 10.5 and d["battery_percentage"] == 78
    assert client.get("/api/v1/drones/SCAR-DRONE-001", headers=DASH).json()["drone_id"] == "SCAR-DRONE-001"
    assert client.get("/api/v1/drones/nope", headers=DASH).status_code == 404


def test_drone_goes_offline_when_telemetry_is_old(client):
    from datetime import datetime, timedelta, timezone
    from app.models import TelemetryRecord
    db = TestingSession()
    old = datetime.now(timezone.utc) - timedelta(minutes=5)
    db.add(TelemetryRecord(drone_id="OLD-1", sequence=1, timestamp=old, received_at=old))
    db.commit()
    db.close()
    assert client.get("/api/v1/drones/OLD-1", headers=DASH).json()["status"] == "offline"
    assert client.get("/api/v1/overview").json()["drones"]["offline"] == 1


def test_online_window_is_short_by_default():
    assert config.ONLINE_WINDOW_SECONDS == 15


def test_drone_track_history(client):
    for seq in range(1, 4):
        pkt = good_packet(seq)
        pkt["timestamp"] = f"2026-11-19T17:0{seq}:00Z"
        pkt["telemetry"]["gps"]["latitude"] = 27.0 + seq
        client.post(URL, json=pkt, headers=DRONE)
    no_gps = good_packet(4)
    no_gps["telemetry"]["gps"] = None
    client.post(URL, json=no_gps, headers=DRONE)
    page = client.get("/api/v1/drones/SCAR-DRONE-001/track", headers=DASH).json()
    assert page["total"] == 3
    assert [p["latitude"] for p in page["items"]] == [30.0, 29.0, 28.0]
    assert set(page["items"][0]) == {"timestamp", "latitude", "longitude", "altitude_m", "battery_percentage"}


def test_drones_require_token(client):
    assert client.get("/api/v1/drones").status_code == 401


def test_telemetry_list_uses_items_total(client):
    for seq in range(1, 4):
        client.post(URL, json=good_packet(seq), headers=DRONE)
    page = client.get(f"{URL}?limit=2", headers=DASH).json()
    assert page["total"] == 3 and len(page["items"]) == 2


# ================= CORS =================
def test_cors_allows_dashboard_origin(client):
    r = client.options("/api/v1/alerts", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_cors_blocks_unknown_origin(client):
    r = client.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers


# ================= sample data =================
def test_seed_adds_and_clears_sample_data(client):
    from app import seed
    db = TestingSession()
    events, points = seed.run(db)
    assert events == 8 and points == 20
    assert client.get(EV).json()["total"] == 8
    assert client.get(f"{EV}?source=wazuh").json()["total"] == 5
    assert client.get(f"{EV}?source=zeek").json()["total"] == 3
    assert client.get("/api/v1/overview").json()["alerts"]["by_severity"]["critical"] == 1
    assert client.get(f"/api/v1/drones/{seed.SAMPLE_DRONE}/track", headers=DASH).json()["total"] == 20
    seed.run(db)
    assert client.get(EV).json()["total"] == 8
    seed.clear(db)
    db.close()
    assert client.get(EV).json()["total"] == 0
    assert client.get("/api/v1/drones", headers=DASH).json()["total"] == 0


# ================= drone token management =================
def test_token_create_rotate_revoke(client):
    from app import drone_tokens
    db = TestingSession()
    token = drone_tokens.create(db, "NEW-DRONE")
    h = {"Authorization": f"Bearer {token}"}
    assert client.post(URL, json=good_packet(drone_id="NEW-DRONE"), headers=h).status_code == 200
    with pytest.raises(ValueError):
        drone_tokens.create(db, "NEW-DRONE")
    new_token = drone_tokens.rotate(db, "NEW-DRONE")
    assert client.post(URL, json=good_packet(2, drone_id="NEW-DRONE"), headers=h).status_code == 401  # old token dead
    h2 = {"Authorization": f"Bearer {new_token}"}
    assert client.post(URL, json=good_packet(2, drone_id="NEW-DRONE"), headers=h2).status_code == 200
    drone_tokens.revoke(db, "NEW-DRONE")
    assert client.post(URL, json=good_packet(3, drone_id="NEW-DRONE"), headers=h2).status_code == 401
    stored = db.query(Drone).filter(Drone.drone_id == "NEW-DRONE").one()
    assert stored.token_hash == hash_token(new_token) and new_token not in stored.token_hash
    db.close()


# ================= migrations =================
LEGACY_SQL = [
    """CREATE TABLE telemetry (id INTEGER NOT NULL, drone_id VARCHAR(50) NOT NULL, sequence INTEGER NOT NULL,
       timestamp DATETIME NOT NULL, altitude_m FLOAT, speed_mps FLOAT, roll_deg FLOAT, pitch_deg FLOAT, yaw_deg FLOAT,
       battery_voltage FLOAT, battery_percentage INTEGER, flight_mode VARCHAR(50), gps_latitude FLOAT,
       gps_longitude FLOAT, gps_satellites INTEGER, received_at DATETIME NOT NULL, PRIMARY KEY (id),
       CONSTRAINT uq_drone_sequence UNIQUE (drone_id, sequence))""",
    "CREATE INDEX ix_telemetry_drone_id ON telemetry (drone_id)",
    "CREATE INDEX ix_telemetry_id ON telemetry (id)",
    """INSERT INTO telemetry (id, drone_id, sequence, timestamp, altitude_m, battery_percentage, received_at)
       VALUES (1, 'D1', 1, '2026-11-01 10:00:00', 12.5, 80, '2026-11-01 10:00:01'),
              (2, 'D1', 2, '2026-11-01 10:00:01', 13.5, 79, '2026-11-01 10:00:02')""",
    """CREATE TABLE security_events (id INTEGER NOT NULL, source VARCHAR(100) NOT NULL, source_alert_id VARCHAR(200),
       title VARCHAR(255), event_type VARCHAR(100) NOT NULL, severity VARCHAR(20) NOT NULL, description TEXT NOT NULL,
       device_ip VARCHAR(45), source_ip VARCHAR(45), destination_ip VARCHAR(45), rule_id VARCHAR(100), raw_event TEXT,
       status VARCHAR(20) NOT NULL, timestamp DATETIME NOT NULL, received_at DATETIME NOT NULL, PRIMARY KEY (id))""",
    """INSERT INTO security_events (id, source, event_type, severity, description, device_ip, status, timestamp, received_at)
       VALUES (1, 'wazuh', 'x', 'high', 'd', '10.0.0.10', 'open', '2026-11-01 10:00:00', '2026-11-01 10:00:00'),
              (2, 'wazuh', 'y', 'low', 'd', NULL, 'acknowledged', '2026-11-01 10:00:00', '2026-11-01 10:00:00')""",
]


def test_migration_upgrades_a_legacy_database_without_losing_data(tmp_path):
    from app.migrations import upgrade_security_event_columns, upgrade_telemetry_table
    from app.models import SecurityEvent, TelemetryRecord
    eng = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with eng.begin() as c:
        for stmt in LEGACY_SQL:
            c.execute(text(stmt))
    for _ in range(2):  # second run must change nothing
        upgrade_security_event_columns(eng)
        upgrade_telemetry_table(eng)
    Base.metadata.create_all(bind=eng)  # creates drones / system_health
    S = sessionmaker(bind=eng)
    with S() as db:
        rows = db.query(TelemetryRecord).order_by(TelemetryRecord.id).all()
        assert [(r.sequence, r.altitude_m, r.boot_id, r.schema_version) for r in rows] == [(1, 12.5, "0", "1.0"), (2, 13.5, "0", "1.0")]
        # the new unique key allows the same sequence under another boot_id
        db.add(TelemetryRecord(drone_id="D1", boot_id="b2", sequence=1, timestamp=rows[0].timestamp, received_at=rows[0].received_at))
        db.commit()
        ev = db.query(SecurityEvent).order_by(SecurityEvent.id).all()
        assert [e.status for e in ev] == ["new", "investigating"]
        assert ev[0].sensor_agent_ip == "10.0.0.10" and ev[0].severity_value is None and ev[0].severity == "high"
        assert ev[0].drone_id is None
    names = {i["name"] for i in inspect(eng).get_indexes("telemetry")}
    assert "ix_telemetry_drone_time" in names
    assert {"drones", "system_health", "telemetry", "security_events"} <= set(inspect(eng).get_table_names())
