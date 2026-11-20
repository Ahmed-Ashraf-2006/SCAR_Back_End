import logging
from sqlalchemy.orm import Session

from app.models import SecurityEvent
from app.schemas import EventCreate, EventStatus

logger = logging.getLogger(__name__)


def create_event(db: Session, data: EventCreate) -> SecurityEvent:
    payload = data.model_dump()
    payload["severity"] = data.severity.value
    event = SecurityEvent(**payload)
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.info("Event saved id=%s type=%s severity=%s", event.id, event.event_type, event.severity)
    return event


def list_events(db: Session, severity: str | None = None, status: str | None = None, limit: int = 100):
    query = db.query(SecurityEvent)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if status:
        query = query.filter(SecurityEvent.status == status)
    return query.order_by(SecurityEvent.id.desc()).limit(limit).all()


def get_event(db: Session, event_id: int):
    return db.get(SecurityEvent, event_id)


def update_status(db: Session, event: SecurityEvent, status: EventStatus):
    event.status = status.value
    db.commit()
    db.refresh(event)
    return event


def delete_event(db: Session, event: SecurityEvent):
    db.delete(event)
    db.commit()
