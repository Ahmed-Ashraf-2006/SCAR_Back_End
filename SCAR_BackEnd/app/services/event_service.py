import json
import logging
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import SENSOR_IP
from app import normalizers
from app.normalizers import wazuh_dedup_key
from app.models import SecurityEvent
from app.schemas import AIAnalysisCreate, AlertWebhookCreate, Disposition, EventCreate, EventStatus, Severity

logger = logging.getLogger(__name__)


def _build(data: EventCreate) -> SecurityEvent:
    payload = data.model_dump()
    payload["severity"] = payload.pop("severity_label").value
    payload["status"] = data.status.value
    if payload.get("raw_event") is not None:
        payload["raw_event"] = json.dumps(payload["raw_event"])
    return SecurityEvent(**payload)


def severity_label_for(level: int) -> str:
    if level <= 6:
        return "low"
    if level <= 9:
        return "medium"
    if level <= 12:
        return "high"
    return "critical"


def _build_webhook_alert(db: Session, data: AlertWebhookCreate) -> SecurityEvent:
    agent = data.agent
    label = data.severity_label.value if data.severity_label else severity_label_for(data.severity)
    event = SecurityEvent(
        source=data.source.value,
        source_alert_id=data.alert_id,
        title=data.rule_description,
        event_type=data.rule_id or "security_alert",
        severity=label,
        severity_value=data.severity,
        description=data.rule_description,
        rule_id=data.rule_id,
        sensor_agent_id=agent.id if agent else None,
        sensor_agent_name=agent.name if agent else None,
        sensor_agent_ip=agent.ip if agent else None,
        device_ip=agent.ip if agent else None,
        sensor_ip=data.sensor_ip or (SENSOR_IP if data.source.value == "zeek" else None),
        source_ip=data.src_ip,
        destination_ip=data.dst_ip,
        raw_event=json.dumps(data.raw),
        status=data.status.value,
        timestamp=data.timestamp,
        sensor_id=data.sensor_id or normalizers.SENSOR_ID,
        src_port=data.src_port,
        dst_port=data.dst_port,
        protocol=data.protocol.strip().lower() if data.protocol and data.protocol.strip() else None,
        # Only Wazuh alerts are de-duplicated here, and only when the origin is known: manager/cluster/sensor_id
        # from the alert, the request, or the SENSOR_ID setting (same key as the raw ingest route). For Zeek the sender's alert_id may be a bare uid, which must not be
        # used alone as a unique event id (Security change request, section 2/3).
        dedup_key=wazuh_dedup_key(data.alert_id, data.raw, agent.id if agent else None, data.sensor_id)
        if data.source.value == "wazuh"
        else None,
    )
    return event


def _find_by_key(db: Session, key: str):
    return db.query(SecurityEvent).filter(SecurityEvent.dedup_key == key).first()


def _save_one(db: Session, event: SecurityEvent):
    """Store one event. Returns (event, created). A duplicate key returns the stored event and created=False."""
    if event.dedup_key:
        existing = _find_by_key(db, event.dedup_key)
        if existing is not None:
            return existing, False
    db.add(event)
    try:
        db.commit()
    except IntegrityError:
        # another request stored the same key between our check and our insert
        db.rollback()
        if event.dedup_key:
            existing = _find_by_key(db, event.dedup_key)
            if existing is not None:
                return existing, False
        raise
    db.refresh(event)
    return event, True


def create_webhook_alert_idempotent(db: Session, data: AlertWebhookCreate):
    """Returns (event, created)."""
    return _save_one(db, _build_webhook_alert(db, data))


def create_webhook_alert(db: Session, data: AlertWebhookCreate) -> SecurityEvent:
    return create_webhook_alert_idempotent(db, data)[0]


def create_event_idempotent(db: Session, data: EventCreate):
    """Returns (event, created). Without a dedup_key it always stores a new event, as before."""
    event, created = _save_one(db, _build(data))
    if created:
        logger.info("Event saved id=%s type=%s severity=%s", event.id, event.event_type, event.severity)
    return event, created


def create_event(db: Session, data: EventCreate) -> SecurityEvent:
    return create_event_idempotent(db, data)[0]


def ingest_events(db: Session, items: list[EventCreate]):
    """Save a batch from the raw ingest route. Returns (new_events, duplicate_ids).

    An event whose dedup_key is already stored (or appears earlier in the same batch) is skipped.
    Events without a key are always stored. Normal case is all-or-nothing in one transaction.
    """
    keys = [d.dedup_key for d in items if d.dedup_key]
    stored = {}
    if keys:
        for key, event_id in db.query(SecurityEvent.dedup_key, SecurityEvent.id).filter(SecurityEvent.dedup_key.in_(keys)):
            stored[key] = event_id

    new_events, duplicate_ids, batch_keys = [], [], {}
    for d in items:
        key = d.dedup_key
        if key and key in stored:
            duplicate_ids.append(stored[key])
        elif key and key in batch_keys:
            duplicate_ids.append(batch_keys[key])  # replaced by the real id after saving, see below
        else:
            event = _build(d)
            new_events.append(event)
            if key:
                batch_keys[key] = event

    # duplicates inside the batch point at an event that is not saved yet: resolve after the commit
    pending = [(i, v) for i, v in enumerate(duplicate_ids) if isinstance(v, SecurityEvent)]
    db.add_all(new_events)
    try:
        db.commit()
    except IntegrityError:
        # race with a parallel request that stored the same key: retry one by one (rare)
        db.rollback()
        new_events, duplicate_ids = [], []
        seen = {}
        for d in items:
            key = d.dedup_key
            if key and key in seen:
                duplicate_ids.append(seen[key])
                continue
            event, created = _save_one(db, _build(d))
            if created:
                new_events.append(event)
            else:
                duplicate_ids.append(event.id)
            if key:
                seen[key] = event.id
    else:
        for e in new_events:
            db.refresh(e)
        for i, v in pending:
            duplicate_ids[i] = v.id
    unkeyed = sum(1 for e in new_events if e.dedup_key is None)
    if unkeyed:
        # counts only, never event contents
        logger.warning(
            "%s of %s stored events have no idempotency key (source origin unknown or no alert id): a resend of "
            "them is not recognised. Set SENSOR_ID (or send manager/sensor_id) to enable duplicate protection.",
            unkeyed, len(new_events),
        )
    logger.info("%s events saved, %s duplicates skipped", len(new_events), len(duplicate_ids))
    return new_events, duplicate_ids


def create_events(db: Session, items: list[EventCreate]) -> list[SecurityEvent]:
    """Save several events (kept for older callers). Duplicate keys are skipped."""
    return ingest_events(db, items)[0]


def _as_utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def list_events(
    db: Session,
    severity_label: str | None = None,
    status: str | None = None,
    disposition: str | None = None,
    source: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
):
    """Returns (items, total). Newest first."""
    query = db.query(SecurityEvent)
    if severity_label:
        query = query.filter(SecurityEvent.severity == severity_label)
    if status:
        query = query.filter(SecurityEvent.status == status)
    if disposition:
        query = query.filter(SecurityEvent.disposition == disposition)
    if source:
        query = query.filter(SecurityEvent.source == source.strip().lower())
    if date_from:
        query = query.filter(SecurityEvent.timestamp >= _as_utc(date_from).astimezone(timezone.utc).replace(tzinfo=None))
    if date_to:
        query = query.filter(SecurityEvent.timestamp <= _as_utc(date_to).astimezone(timezone.utc).replace(tzinfo=None))
    total = query.count()
    items = (
        query.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return items, total


def get_event(db: Session, event_id: int):
    return db.get(SecurityEvent, event_id)


def update_ai_analysis(db: Session, event: SecurityEvent, data: AIAnalysisCreate) -> SecurityEvent:
    """Attach or replace the AI team's latest analysis on an existing event."""
    event.ai_severity_label = data.severity.value
    event.agent_name = data.agent_name
    event.model_version = data.model_version
    event.risk_score = data.risk_score
    event.category = data.category
    event.confidence = data.confidence
    event.explanation = data.explanation
    event.recommended_action = data.recommended_action
    event.created_at = data.created_at
    db.commit()
    db.refresh(event)
    return event


def update_status_and_disposition(db: Session, event: SecurityEvent, body) -> SecurityEvent:
    """Change the workflow status, the disposition (classification), or both. Only what was sent changes."""
    if body.status is not None:
        event.status = body.status.value
    if "disposition" in body.model_fields_set:  # an explicit null clears it
        event.disposition = body.disposition.value if body.disposition else None
    db.commit()
    db.refresh(event)
    return event


def update_status(db: Session, event: SecurityEvent, status: EventStatus):
    event.status = status.value
    db.commit()
    db.refresh(event)
    return event


def delete_event(db: Session, event: SecurityEvent):
    db.delete(event)
    db.commit()


def alert_counts(db: Session) -> dict:
    """Counts used by the dashboard overview."""
    severities = [s.value for s in Severity]
    statuses = [s.value for s in EventStatus]

    by_severity = dict.fromkeys(severities, 0)
    for sev, n in db.query(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity):
        if sev in by_severity:
            by_severity[sev] = n

    by_status = dict.fromkeys(statuses, 0)
    for st, n in db.query(SecurityEvent.status, func.count()).group_by(SecurityEvent.status):
        if st in by_status:
            by_status[st] = n

    by_disposition = dict.fromkeys([d.value for d in Disposition], 0)
    for dp, n in db.query(SecurityEvent.disposition, func.count()).group_by(SecurityEvent.disposition):
        if dp in by_disposition:
            by_disposition[dp] = n

    new_by_severity = dict.fromkeys(severities, 0)
    new_rows = (
        db.query(SecurityEvent.severity, func.count())
        .filter(SecurityEvent.status == EventStatus.new.value)
        .group_by(SecurityEvent.severity)
    )
    for sev, n in new_rows:
        if sev in new_by_severity:
            new_by_severity[sev] = n

    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_disposition": by_disposition,
        "new_by_severity": new_by_severity,
    }
