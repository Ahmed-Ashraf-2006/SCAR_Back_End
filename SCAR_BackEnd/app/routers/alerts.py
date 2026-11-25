import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SecurityEvent
from app.routers.common import event_filters
from app.schemas import (
    AgentInfo,
    AlertOut,
    AlertWebhookCreate,
    AlertWebhookOut,
    EventOut,
    EventStatusUpdate,
    Page,
)
from app.security import require_security_token, require_token
from app.services import event_service

logger = logging.getLogger(__name__)

# Reads stay open for the dashboard. Webhook writes need the security token; status changes need the dashboard token.
router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


def to_alert(e: SecurityEvent) -> AlertOut:
    return AlertOut(
        id=e.id,
        event_id=e.id,
        alert_id=e.source_alert_id,
        title=e.title or e.event_type,
        severity=e.severity_value,
        severity_label=e.severity,
        source=e.source,
        source_alert_id=e.source_alert_id,
        status=e.status,
        disposition=e.disposition,
        timestamp=e.timestamp,
        description=e.description,
        agent=AgentInfo(id=e.sensor_agent_id, name=e.sensor_agent_name, ip=e.sensor_agent_ip)
        if e.agent
        else None,
        sensor_ip=e.sensor_ip,
        sensor_id=e.sensor_id,
        src_ip=e.source_ip,
        dst_ip=e.destination_ip,
        src_port=e.src_port,
        dst_port=e.dst_port,
        protocol=e.protocol,
        zeek_uid=e.zeek_uid,
        agent_name=e.agent_name,
        model_version=e.model_version,
        ai_severity_label=e.ai_severity_label,
        risk_score=e.risk_score,
        category=e.category,
        confidence=e.confidence,
        explanation=e.explanation,
        recommended_action=e.recommended_action,
        created_at=e.created_at,
    )


@router.post("", response_model=AlertWebhookOut, status_code=status.HTTP_201_CREATED)
def receive_alert(
    data: AlertWebhookCreate,
    response: Response,
    db: Session = Depends(get_db),
    _=Depends(require_security_token),
):
    """Receive the agreed Wazuh/Zeek alert format through the authenticated webhook.

    A Wazuh alert that was already stored (same alert_id) is not stored again: the existing alert is
    returned with 200 instead of 201.
    """
    event, created = event_service.create_webhook_alert_idempotent(db, data)
    if not created:
        response.status_code = status.HTTP_200_OK
    elif event.dedup_key is None and event.source == "wazuh":
        logger.warning("A Wazuh alert was stored without an idempotency key (origin unknown): set SENSOR_ID or send sensor_id/manager.")
    raw = event.raw_event
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            pass
    return AlertWebhookOut(
        event_id=event.id,
        alert_id=event.source_alert_id,
        timestamp=event.timestamp,
        source=event.source,
        rule_id=event.rule_id,
        rule_description=event.description,
        severity=event.severity_value,
        severity_label=event.severity,
        agent=AgentInfo(id=event.sensor_agent_id, name=event.sensor_agent_name, ip=event.sensor_agent_ip)
        if event.agent
        else None,
        src_ip=event.source_ip,
        dst_ip=event.destination_ip,
        sensor_ip=event.sensor_ip,
        sensor_id=event.sensor_id,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        status=event.status,
        raw=raw,
    )


@router.get("", response_model=Page[AlertOut])
def list_alerts(filters: dict = Depends(event_filters), db: Session = Depends(get_db)):
    items, total = event_service.list_events(db, **filters)
    return Page[AlertOut](items=[to_alert(e) for e in items], total=total)


@router.get("/{alert_id}", response_model=EventOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    event = event_service.get_event(db, alert_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return event


@router.patch("/{alert_id}/status", response_model=EventOut, dependencies=[Depends(require_token)])
def change_alert_status(alert_id: int, body: EventStatusUpdate, db: Session = Depends(get_db)):
    event = event_service.get_event(db, alert_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return event_service.update_status_and_disposition(db, event, body)
