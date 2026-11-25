"""Tables for the PROPOSED AI-contract adapter (separate from security_events on purpose).

Prefixed ai_ so nothing in the existing API or tables changes. Owners/shape come from the AI team's
DRAFT docs/contracts.md (not yet agreed by the backend team)."""
from sqlalchemy import JSON, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models import UTCDateTime, utcnow


class AIMission(Base):
    __tablename__ = "ai_missions"
    mission_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    drone_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    zone_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="planned")
    created_at: Mapped[object] = mapped_column(UTCDateTime, default=utcnow)


class AIEvent(Base):
    __tablename__ = "ai_events"
    event_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    mission_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(20))
    event_type: Mapped[str] = mapped_column(String(100))
    timestamp: Mapped[object] = mapped_column(UTCDateTime, default=utcnow)
    bssid: Mapped[str | None] = mapped_column(String(50), nullable=True)
    ssid: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rssi: Mapped[int | None] = mapped_column(Integer, nullable=True)
    channel: Mapped[int | None] = mapped_column(Integer, nullable=True)
    encryption: Mapped[str | None] = mapped_column(String(20), nullable=True)
    lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    altitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    status_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    claimed_at: Mapped[object | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[object] = mapped_column(UTCDateTime, default=utcnow)
    __table_args__ = (Index("ix_ai_events_status_created", "status", "created_at"),)


class AIAnalysisResult(Base):
    """One row per (event, agent, model_version): the 3 agent results are kept, never overwritten."""
    __tablename__ = "ai_analysis_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(100), index=True)
    agent: Mapped[str] = mapped_column(String(50))
    model_version: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    risk_score: Mapped[int] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(Text, default="")
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    processing_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[object] = mapped_column(UTCDateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("event_id", "agent", "model_version", name="uq_ai_result"),)


class AIWorkflowRun(Base):
    __tablename__ = "ai_workflow_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workflow_name: Mapped[str] = mapped_column(String(100))
    event_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    n8n_execution_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20))
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    finished_at: Mapped[object] = mapped_column(UTCDateTime, default=utcnow)


class AIAlert(Base):
    __tablename__ = "ai_alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    channel: Mapped[str | None] = mapped_column(String(50), nullable=True)
    delivery: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_at: Mapped[object] = mapped_column(UTCDateTime, default=utcnow)


class AIReport(Base):
    __tablename__ = "ai_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mission_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    format: Mapped[str | None] = mapped_column(String(20), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[object] = mapped_column(UTCDateTime, default=utcnow)
