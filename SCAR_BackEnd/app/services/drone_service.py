"""Health messages and security events that a drone sends about itself (PROPOSED contract)."""
import json
import logging

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import SecurityEvent, SystemHealth
from app.schemas import DroneEventCreate, GapInfo, HealthCreate, HealthData, HealthOut
from app.services.gaps import find_gap

logger = logging.getLogger(__name__)


class DuplicateMessageError(Exception):
    """Same drone_id + boot_id + sequence was already stored for this stream."""


def create_health(db: Session, data: HealthCreate) -> tuple[SystemHealth, GapInfo | None]:
    keys = [SystemHealth.drone_id == data.drone_id, SystemHealth.boot_id == data.boot_id]
    if db.query(SystemHealth.id).filter(*keys, SystemHealth.sequence == data.sequence).first():
        raise DuplicateMessageError()
    gap = find_gap(db, SystemHealth.sequence, keys, data.sequence)
    h = data.health
    record = SystemHealth(
        drone_id=data.drone_id, boot_id=data.boot_id, schema_version=data.schema_version,
        sequence=data.sequence, timestamp=data.timestamp,
        overall_status=h.overall_status, cpu_percent=h.cpu_percent, memory_percent=h.memory_percent,
        cpu_temp_c=h.cpu_temp_c, storage_percent=h.storage_percent, link_rssi_dbm=h.link_rssi_dbm,
        uptime_s=h.uptime_s, components=json.dumps(h.components) if h.components is not None else None,
    )
    try:
        db.add(record)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise DuplicateMessageError()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Database error while saving health")
        raise
    db.refresh(record)
    return record, gap


def health_to_out(r: SystemHealth) -> HealthOut:
    return HealthOut(
        id=r.id, drone_id=r.drone_id, schema_version=r.schema_version, boot_id=r.boot_id,
        sequence=r.sequence, timestamp=r.timestamp, received_at=r.received_at,
        health=HealthData(
            overall_status=r.overall_status, cpu_percent=r.cpu_percent, memory_percent=r.memory_percent,
            cpu_temp_c=r.cpu_temp_c, storage_percent=r.storage_percent, link_rssi_dbm=r.link_rssi_dbm,
            uptime_s=r.uptime_s, components=json.loads(r.components) if r.components else None,
        ),
    )


def latest_health(db: Session, drone_id: str) -> SystemHealth | None:
    return (
        db.query(SystemHealth).filter(SystemHealth.drone_id == drone_id)
        .order_by(SystemHealth.timestamp.desc(), SystemHealth.sequence.desc()).first()
    )


def create_drone_event(db: Session, data: DroneEventCreate) -> tuple[SecurityEvent, GapInfo | None]:
    keys = [SecurityEvent.drone_id == data.drone_id, SecurityEvent.boot_id == data.boot_id]
    if db.query(SecurityEvent.id).filter(*keys, SecurityEvent.event_sequence == data.sequence).first():
        raise DuplicateMessageError()
    # a retry of the same event with a new sequence number is also caught through its unique id
    if db.query(SecurityEvent.id).filter(
        SecurityEvent.source == "drone", SecurityEvent.drone_id == data.drone_id,
        SecurityEvent.source_alert_id == data.event_uid,
    ).first():
        raise DuplicateMessageError()
    gap = find_gap(db, SecurityEvent.event_sequence, keys, data.sequence)
    event = SecurityEvent(
        source="drone", source_alert_id=data.event_uid, title=data.title or data.event_type,
        event_type=data.event_type, severity=data.severity_label.value, severity_value=None,
        description=data.description, rule_id=data.rule_id,
        raw_event=json.dumps(data.raw) if data.raw is not None else None,
        status="new", timestamp=data.timestamp,
        drone_id=data.drone_id, boot_id=data.boot_id, event_sequence=data.sequence,
        schema_version=data.schema_version,
    )
    try:
        db.add(event)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Database error while saving drone event")
        raise
    db.refresh(event)
    return event, gap
