"""PROPOSED adapter for the AI team's DRAFT contract (docs/contracts.md section 4.1).

Root-level paths, header `X-API-Key`. Separate from /api/v1 (unchanged). Stores in ai_* tables.
NOT team-approved: path style, auth style, event model and storage still need the team's decision.
"""
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import config
from app.ai_contract_models import AIAlert, AIAnalysisResult, AIEvent, AIMission, AIReport, AIWorkflowRun
from app.database import get_db

logger = logging.getLogger(__name__)


def require_ai_api_key(x_api_key: Optional[str] = Header(default=None)):
    expected = config.AI_CONTRACT_API_KEY
    if not expected:
        logger.error("AI_CONTRACT_API_KEY is not set in the environment / .env file")
        raise HTTPException(status_code=500, detail="Server authentication is not configured")
    if x_api_key is None or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


router = APIRouter(tags=["AI Contract (PROPOSED)"], dependencies=[Depends(require_ai_api_key)])

STATUSES = ("pending", "processing", "analyzed", "failed")


def _iso(v):
    if v is None:
        return None
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    return v.isoformat()


def _event_out(e: AIEvent) -> dict:
    return {
        "event_id": e.event_id, "mission_id": e.mission_id, "source": e.source, "event_type": e.event_type,
        "timestamp": _iso(e.timestamp), "bssid": e.bssid, "ssid": e.ssid, "rssi": e.rssi, "channel": e.channel,
        "encryption": e.encryption, "lat": e.lat, "lon": e.lon, "altitude": e.altitude,
        "raw_payload": e.raw_payload or {}, "status": e.status, "status_error": e.status_error,
        "claimed_at": _iso(e.claimed_at), "created_at": _iso(e.created_at),
    }


def _result_out(r: AIAnalysisResult) -> dict:
    return {
        "event_id": r.event_id, "agent": r.agent, "model_version": r.model_version, "severity": r.severity,
        "risk_score": r.risk_score, "category": r.category, "confidence": r.confidence,
        "explanation": r.explanation, "recommended_action": r.recommended_action, "features": r.features or {},
        "processing_ms": r.processing_ms, "error": r.error, "created_at": _iso(r.created_at),
    }


class EventIn(BaseModel):
    event_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    mission_id: Optional[str] = None
    source: Literal["wazuh", "zeek", "drone"]
    event_type: str = Field(min_length=1, max_length=100)
    timestamp: Optional[datetime] = None
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    rssi: Optional[int] = None
    channel: Optional[int] = None
    encryption: Optional[Literal["Open", "WEP", "WPA", "WPA2", "WPA3", "Unknown"]] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    altitude: Optional[float] = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class StatusIn(BaseModel):
    status: Literal["pending", "processing", "analyzed", "failed"]
    error: Optional[str] = None


class RequeueIn(BaseModel):
    older_than_seconds: int = Field(default=300, ge=0)


class ResultRow(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    event_id: Optional[str] = None
    agent: str = Field(min_length=1, max_length=50)
    model_version: str = Field(min_length=1, max_length=100)
    severity: Literal["low", "medium", "high", "critical"]
    risk_score: int = Field(ge=0, le=100)
    category: str = Field(min_length=1, max_length=50)
    confidence: float = Field(ge=0, le=1)
    explanation: str = ""
    recommended_action: str = ""
    features: dict[str, Any] = Field(default_factory=dict)
    processing_ms: Optional[int] = None
    error: Optional[str] = None


class BulkIn(BaseModel):
    event_id: Optional[str] = None
    results: list[ResultRow] = Field(min_length=1)


class MissionIn(BaseModel):
    mission_id: str = Field(min_length=1, max_length=100)
    drone_id: Optional[str] = None
    zone_id: Optional[str] = None
    status: Literal["planned", "in_flight", "completed", "aborted"] = "planned"


class WorkflowRunIn(BaseModel):
    workflow_name: str = Field(min_length=1, max_length=100)
    event_id: Optional[str] = None
    mission_id: Optional[str] = None
    n8n_execution_id: Optional[str] = None
    status: Literal["success", "failed", "skipped"]
    attempts: int = 1
    error_message: Optional[str] = None


class AlertIn(BaseModel):
    event_id: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    category: Optional[str] = None
    message: Optional[str] = None
    channel: Optional[str] = None
    delivery: Optional[str] = None


class ReportIn(BaseModel):
    mission_id: Optional[str] = None
    format: Optional[str] = None
    content: Optional[str] = None


def _get_event_or_404(db: Session, event_id: str) -> AIEvent:
    e = db.get(AIEvent, event_id)
    if e is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return e


@router.post("/events", status_code=201)
def create_event(data: EventIn, response: Response, db: Session = Depends(get_db)):
    """Idempotent on event_id: a repeat returns the stored event (200) and changes nothing."""
    event_id = data.event_id or str(uuid.uuid4())
    existing = db.get(AIEvent, event_id)
    if existing is not None:
        response.status_code = 200
        return _event_out(existing)
    e = AIEvent(
        event_id=event_id, mission_id=data.mission_id, source=data.source, event_type=data.event_type,
        timestamp=data.timestamp or datetime.now(timezone.utc), bssid=data.bssid, ssid=data.ssid,
        rssi=data.rssi, channel=data.channel, encryption=data.encryption, lat=data.lat, lon=data.lon,
        altitude=data.altitude, raw_payload=data.raw_payload, status="pending",
    )
    db.add(e)
    db.commit()
    db.refresh(e)
    return _event_out(e)


@router.get("/events")
def list_events(status: Optional[str] = None, limit: int = 50, db: Session = Depends(get_db)):
    if status is not None and status not in STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")
    limit = max(1, min(limit, 500))
    q = select(AIEvent)
    if status:
        q = q.where(AIEvent.status == status)
    rows = db.scalars(q.order_by(AIEvent.created_at.asc(), AIEvent.event_id.asc()).limit(limit)).all()
    return [_event_out(e) for e in rows]


@router.post("/events/requeue-stuck")
def requeue_stuck(body: RequeueIn = RequeueIn(), db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=body.older_than_seconds)
    res = db.execute(
        update(AIEvent)
        .where(AIEvent.status == "processing", AIEvent.claimed_at < cutoff)
        .values(status="pending", claimed_at=None)
    )
    db.commit()
    return {"requeued": res.rowcount or 0}


@router.get("/events/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db)):
    return _event_out(_get_event_or_404(db, event_id))


@router.get("/events/{event_id}/analysis-results")
def event_results(event_id: str, db: Session = Depends(get_db)):
    _get_event_or_404(db, event_id)
    rows = db.scalars(select(AIAnalysisResult).where(AIAnalysisResult.event_id == event_id).order_by(AIAnalysisResult.id)).all()
    return [_result_out(r) for r in rows]


@router.post("/events/{event_id}/claim")
def claim_event(event_id: str, db: Session = Depends(get_db)):
    """Atomic pending -> processing (one UPDATE with a status guard). 409 if not pending."""
    _get_event_or_404(db, event_id)
    res = db.execute(
        update(AIEvent)
        .where(AIEvent.event_id == event_id, AIEvent.status == "pending")
        .values(status="processing", claimed_at=datetime.now(timezone.utc))
    )
    db.commit()
    e = db.get(AIEvent, event_id)
    db.refresh(e)
    if (res.rowcount or 0) != 1:
        raise HTTPException(status_code=409, detail=f"Event is already {e.status}")
    return _event_out(e)


@router.patch("/events/{event_id}/status")
def set_status(event_id: str, body: StatusIn, db: Session = Depends(get_db)):
    e = _get_event_or_404(db, event_id)
    e.status = body.status
    e.status_error = body.error
    if body.status != "processing":
        e.claimed_at = None if body.status == "pending" else e.claimed_at
    db.commit()
    db.refresh(e)
    return _event_out(e)


@router.post("/analysis-results/bulk", status_code=201)
def save_results_bulk(body: BulkIn, db: Session = Depends(get_db)):
    """Upsert on (event_id, agent, model_version). Different agents never overwrite each other."""
    prepared = []
    for r in body.results:
        eid = r.event_id or body.event_id
        if not eid:
            raise HTTPException(status_code=422, detail="event_id is required (top level or per row)")
        prepared.append((eid, r))
    for eid in {p[0] for p in prepared}:
        _get_event_or_404(db, eid)
    for eid, r in prepared:
        row = db.scalars(
            select(AIAnalysisResult).where(
                AIAnalysisResult.event_id == eid, AIAnalysisResult.agent == r.agent,
                AIAnalysisResult.model_version == r.model_version,
            )
        ).first()
        values = r.model_dump(exclude={"event_id", "agent", "model_version"})
        if row is None:
            db.add(AIAnalysisResult(event_id=eid, agent=r.agent, model_version=r.model_version, **values))
        else:
            for k, v in values.items():
                setattr(row, k, v)
    db.commit()
    return {"saved": len(prepared)}


@router.post("/missions", status_code=201)
def upsert_mission(body: MissionIn, db: Session = Depends(get_db)):
    m = db.get(AIMission, body.mission_id)
    if m is None:
        m = AIMission(mission_id=body.mission_id)
        db.add(m)
    m.drone_id, m.zone_id, m.status = body.drone_id, body.zone_id, body.status
    db.commit()
    return {"mission_id": m.mission_id, "drone_id": m.drone_id, "zone_id": m.zone_id, "status": m.status}


@router.get("/missions/{mission_id}")
def get_mission(mission_id: str, db: Session = Depends(get_db)):
    m = db.get(AIMission, mission_id)
    if m is None:
        # the mock returns {mission_id} for an unknown id; contract does not define 404 here
        return {"mission_id": mission_id}
    return {"mission_id": m.mission_id, "drone_id": m.drone_id, "zone_id": m.zone_id, "status": m.status,
            "created_at": _iso(m.created_at)}


@router.get("/missions/{mission_id}/events")
def mission_events(mission_id: str, db: Session = Depends(get_db)):
    rows = db.scalars(select(AIEvent).where(AIEvent.mission_id == mission_id).order_by(AIEvent.created_at.asc())).all()
    return [_event_out(e) for e in rows]


@router.get("/missions/{mission_id}/analysis-results")
def mission_results(mission_id: str, agent: Optional[str] = None, db: Session = Depends(get_db)):
    ids = select(AIEvent.event_id).where(AIEvent.mission_id == mission_id)
    q = select(AIAnalysisResult).where(AIAnalysisResult.event_id.in_(ids))
    if agent:
        q = q.where(AIAnalysisResult.agent == agent)
    return [_result_out(r) for r in db.scalars(q.order_by(AIAnalysisResult.id)).all()]


@router.post("/workflow-runs", status_code=201)
def log_workflow_run(body: WorkflowRunIn, db: Session = Depends(get_db)):
    db.add(AIWorkflowRun(**body.model_dump()))
    db.commit()
    return {"ok": True}


@router.post("/alerts", status_code=201)
def store_alert(body: AlertIn, db: Session = Depends(get_db)):
    db.add(AIAlert(**body.model_dump()))
    db.commit()
    return {"ok": True}


@router.post("/reports", status_code=201)
def store_report(body: ReportIn, db: Session = Depends(get_db)):
    db.add(AIReport(**body.model_dump()))
    db.commit()
    return {"ok": True}
