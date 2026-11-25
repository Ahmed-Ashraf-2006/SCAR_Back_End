"""Put SAMPLE data in the database so the dashboard can be tested.

    python -m app.seed            add sample data (replaces any earlier sample data)
    python -m app.seed --clear    remove only the sample data

All of this data is FAKE. Sample rows are easy to recognise:
  * events have a source_alert_id that starts with "sample-"
  * the drone is called SAMPLE-DRONE-001
The sample raw events are passed through the real normalizers, so they also exercise the ingest logic.
"""
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app import models  # noqa: F401  (registers the tables)
from app.database import Base, SessionLocal, engine
from app.models import SecurityEvent, TelemetryRecord
from app.normalizers import normalize
from app.schemas import EventStatus
from app.services import event_service

SAMPLE_DRONE = "SAMPLE-DRONE-001"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _sample_raw_events(now: datetime):
    """(source, raw_event, status) - Wazuh and Zeek examples in their original style."""
    m = lambda minutes: now - timedelta(minutes=minutes)  # noqa: E731
    return [
        ("wazuh", {"id": "sample-w-1", "timestamp": _iso(m(58)),
                   "rule": {"id": "5710", "level": 5, "description": "sshd: attempt to login using a non-existent user", "groups": ["authentication_failed"]},
                   "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.10"},
                   "data": {"srcip": "203.0.113.7"}}, "resolved"),
        ("wazuh", {"id": "sample-w-2", "timestamp": _iso(m(44)),
                   "rule": {"id": "5712", "level": 10, "description": "sshd: brute force attack", "groups": ["authentication_failures"]},
                   "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.10"},
                   "data": {"srcip": "203.0.113.7"}}, "investigating"),
        ("wazuh", {"id": "sample-w-3", "timestamp": _iso(m(30)),
                   "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed", "groups": ["syscheck"]},
                   "agent": {"id": "002", "name": "db-01", "ip": "10.0.0.20"}}, "new"),
        ("wazuh", {"id": "sample-w-4", "timestamp": _iso(m(12)),
                   "rule": {"id": "100100", "level": 14, "description": "Possible privilege escalation", "groups": ["privilege_escalation"]},
                   "agent": {"id": "002", "name": "db-01", "ip": "10.0.0.20"}}, "new"),
        ("wazuh", {"id": "sample-w-5", "timestamp": _iso(m(5)),
                   "rule": {"id": "31101", "level": 6, "description": "Web server 400 error code", "groups": ["web"]},
                   "agent": {"id": "003", "name": "web-02", "ip": "10.0.0.11"},
                   "data": {"srcip": "198.51.100.23"}}, "new"),
        ("zeek", {"ts": (m(35)).timestamp(), "uid": "sample-z-2", "note": "Scan::Port_Scan",
                  "msg": "198.51.100.5 scanned 20 unique ports of host 10.0.0.10", "src": "198.51.100.5", "dst": "10.0.0.10"}, "investigating"),
        ("zeek", {"ts": (m(22)).timestamp(), "uid": "sample-z-3", "note": "SSH::Password_Guessing",
                  "msg": "203.0.113.7 appears to be guessing SSH passwords", "src": "203.0.113.7", "dst": "10.0.0.10"}, "new"),
        ("zeek", {"ts": (m(9)).timestamp(), "uid": "sample-z-4", "note": "SSL::Invalid_Server_Cert",
                  "msg": "SSL certificate validation failed", "id": {"orig_h": "10.0.0.11", "resp_h": "192.0.2.44"}}, "new"),
    ]


def clear(db: Session) -> None:
    db.query(TelemetryRecord).filter(TelemetryRecord.drone_id == SAMPLE_DRONE).delete(synchronize_session=False)
    db.query(SecurityEvent).filter(SecurityEvent.source_alert_id.like("sample-%")).delete(synchronize_session=False)
    db.commit()


def add_sample_events(db: Session, now: datetime) -> int:
    count = 0
    for source, raw, status in _sample_raw_events(now):
        normalized = normalize(source, raw)
        if normalized is None:
            continue
        event = event_service.create_event(db, normalized)
        if status != EventStatus.new.value:
            event_service.update_status(db, event, EventStatus(status))
        count += 1
    return count


def add_sample_telemetry(db: Session, now: datetime, points: int = 20) -> int:
    for i in range(points):
        moment = now - timedelta(seconds=30 * (points - 1 - i))
        db.add(
            TelemetryRecord(
                drone_id=SAMPLE_DRONE,
                sequence=i + 1,
                timestamp=moment,
                received_at=moment,
                altitude_m=10 + i * 0.5,
                speed_mps=3.0,
                battery_percentage=90 - i,
                flight_mode="AUTO",
                gps_latitude=30.0444 + 0.0005 * i,
                gps_longitude=31.2357 + 0.0004 * i,
                gps_satellites=9,
            )
        )
    db.commit()
    return points


def run(db: Session, now: datetime | None = None) -> tuple[int, int]:
    now = now or datetime.now(timezone.utc)
    clear(db)
    return add_sample_events(db, now), add_sample_telemetry(db, now)


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        if "--clear" in sys.argv:
            clear(session)
            print("Sample data removed.")
        else:
            events, points = run(session)
            print(f"Added {events} sample events and {points} sample telemetry points for {SAMPLE_DRONE}.")
            print("Remove them with: python -m app.seed --clear")
