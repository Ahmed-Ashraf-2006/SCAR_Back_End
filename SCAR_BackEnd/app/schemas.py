import ipaddress
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Generic, Optional, TypeVar

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


from app.config import SUPPORTED_SCHEMA_MAJORS

_VERSION_RE = re.compile(r"^\d+\.\d+$")
_BOOT_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


def _check_version(v: str) -> str:
    """Schema version is "major.minor". Unknown major versions are rejected, newer minors are accepted."""
    v = v.strip()
    if not _VERSION_RE.match(v):
        raise ValueError("schema_version must look like \"1.0\"")
    if int(v.split(".")[0]) not in SUPPORTED_SCHEMA_MAJORS:
        supported = ", ".join(str(m) for m in sorted(SUPPORTED_SCHEMA_MAJORS))
        raise ValueError(f"unsupported schema major version (supported: {supported})")
    return v


def _check_boot(v: str) -> str:
    v = v.strip()
    if not _BOOT_RE.match(v):
        raise ValueError("boot_id may only contain letters, digits and . _ : -")
    return v


def _now():
    return datetime.now(timezone.utc)


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Every list endpoint returns this shape (requested by the dashboard)."""

    items: list[T]
    total: int


# ---------- Telemetry (follows the team handoff spec) ----------
# Any sensor value that is unavailable must be null - we never fill in a default.
# The numeric ranges below are PROPOSED sanity limits - confirm with Abdelrhman.
class GpsData(BaseModel):
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    satellites: Optional[int] = Field(default=None, ge=0)

    @model_validator(mode="after")
    def lat_and_lon_together(self):
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be sent together")
        return self


class TelemetryData(BaseModel):
    altitude_m: Optional[float] = Field(default=None, ge=-100, le=10000)
    speed_mps: Optional[float] = Field(default=None, ge=0, le=200)
    roll_deg: Optional[float] = Field(default=None, ge=-180, le=180)
    pitch_deg: Optional[float] = Field(default=None, ge=-90, le=90)
    yaw_deg: Optional[float] = Field(default=None, ge=-360, le=360)
    battery_voltage: Optional[float] = Field(default=None, ge=0)
    battery_percentage: Optional[int] = Field(default=None, ge=0, le=100)
    flight_mode: Optional[str] = Field(default=None, max_length=50)
    system_status: Optional[str] = Field(default=None, max_length=50)  # compact status, e.g. ok / degraded / failsafe
    gps: Optional[GpsData] = None


class TelemetryCreate(BaseModel):
    drone_id: str = Field(min_length=1, max_length=50)
    schema_version: str = Field(default="1.0", max_length=20)  # PROPOSED contract; optional until approved
    boot_id: str = Field(default="0", min_length=1, max_length=64)  # changes every time the drone restarts
    timestamp: datetime
    sequence: int = Field(ge=0)
    telemetry: TelemetryData

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v):
        return _check_version(v)

    @field_validator("boot_id")
    @classmethod
    def check_boot(cls, v):
        return _check_boot(v)

    @field_validator("drone_id")
    @classmethod
    def clean_drone_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("drone_id must not be empty")
        return v

    @field_validator("timestamp")
    @classmethod
    def fix_timestamp(cls, v):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

class GapInfo(BaseModel):
    """Sequence numbers that were skipped just before this packet (packets lost on the way)."""

    expected_sequence: int
    received_sequence: int
    missing: int


class TelemetryAccepted(BaseModel):
    status: str = "accepted"
    drone_id: str
    sequence: int
    gap: Optional[GapInfo] = None


class TelemetryOut(BaseModel):
    id: int
    drone_id: str
    schema_version: str = "1.0"
    boot_id: str = "0"
    sequence: int
    timestamp: datetime
    received_at: datetime
    telemetry: TelemetryData


# ---------- System health and drone events (PROPOSED contract - not approved yet) ----------
class HealthData(BaseModel):
    overall_status: Optional[str] = Field(default=None, max_length=50)
    cpu_percent: Optional[float] = Field(default=None, ge=0, le=100)
    memory_percent: Optional[float] = Field(default=None, ge=0, le=100)
    cpu_temp_c: Optional[float] = Field(default=None, ge=-40, le=150)
    storage_percent: Optional[float] = Field(default=None, ge=0, le=100)
    link_rssi_dbm: Optional[float] = Field(default=None, ge=-150, le=0)
    uptime_s: Optional[int] = Field(default=None, ge=0)
    components: Optional[dict[str, str]] = None  # e.g. {"gps": "ok", "camera": "degraded"}


class _DroneMessage(BaseModel):
    drone_id: str = Field(min_length=1, max_length=50)
    schema_version: str = Field(default="1.0", max_length=20)
    boot_id: str = Field(default="0", min_length=1, max_length=64)
    sequence: int = Field(ge=0)
    timestamp: datetime

    @field_validator("drone_id")
    @classmethod
    def clean_drone_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("drone_id must not be empty")
        return v

    @field_validator("schema_version")
    @classmethod
    def check_version(cls, v):
        return _check_version(v)

    @field_validator("boot_id")
    @classmethod
    def check_boot(cls, v):
        return _check_boot(v)

    @field_validator("timestamp")
    @classmethod
    def fix_timestamp(cls, v):
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v


class HealthCreate(_DroneMessage):
    health: HealthData


class HealthOut(BaseModel):
    id: int
    drone_id: str
    schema_version: str
    boot_id: str
    sequence: int
    timestamp: datetime
    received_at: datetime
    health: HealthData


class DroneEventCreate(_DroneMessage):
    event_uid: str = Field(min_length=1, max_length=200)  # unique id made by the drone
    event_type: str = Field(min_length=1, max_length=100)
    severity_label: "Severity"
    title: Optional[str] = Field(default=None, max_length=255)
    description: str = ""
    rule_id: Optional[str] = Field(default=None, max_length=100)
    raw: Optional[dict[str, Any]] = None


class DroneEventAccepted(BaseModel):
    status: str = "accepted"
    event_id: int
    drone_id: str
    sequence: int
    gap: Optional[GapInfo] = None


# ---------- Security events (proposed format - confirm with security team) ----------
class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EventStatus(str, Enum):
    new = "new"
    investigating = "investigating"
    resolved = "resolved"


class Disposition(str, Enum):
    """How the analyst classified the alert. Separate from EventStatus (the workflow state)."""
    false_positive = "false_positive"


class EventCreate(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    source_alert_id: Optional[str] = Field(default=None, max_length=200)  # original ID from Zeek / Wazuh
    title: Optional[str] = Field(default=None, max_length=255)
    event_type: str = Field(min_length=1, max_length=100)
    severity_label: Severity
    severity_value: Optional[int] = Field(default=None, ge=0, le=15)
    description: str = ""
    device_ip: Optional[str] = Field(default=None, max_length=45)
    sensor_agent_id: Optional[str] = Field(default=None, max_length=100)
    sensor_agent_name: Optional[str] = Field(default=None, max_length=100)
    sensor_agent_ip: Optional[str] = Field(default=None, max_length=45)
    sensor_ip: Optional[str] = Field(default=None, max_length=45)
    source_ip: Optional[str] = Field(default=None, max_length=45)
    destination_ip: Optional[str] = Field(default=None, max_length=45)
    rule_id: Optional[str] = Field(default=None, max_length=100)
    sensor_id: Optional[str] = Field(default=None, max_length=100)
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = Field(default=None, max_length=20)  # lower-cased; allowed values are Needs Confirmation
    zeek_uid: Optional[str] = Field(default=None, max_length=100)
    # Optional: send the same key again and the event is treated as a duplicate (nothing new is stored).
    dedup_key: Optional[str] = Field(default=None, min_length=1, max_length=400)
    raw_event: Optional[dict[str, Any] | str] = None  # original Zeek/Wazuh event
    timestamp: datetime = Field(default_factory=_now)
    status: EventStatus = EventStatus.new

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, v):
        v = v.strip().lower() if v is not None else None
        return v or None

    @field_validator("timestamp")
    @classmethod
    def fix_timestamp(cls, v):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("source")
    @classmethod
    def normalize_source(cls, v):
        return v.strip().lower()

    @field_validator("device_ip", "sensor_agent_ip", "sensor_ip", "source_ip", "destination_ip")
    @classmethod
    def check_event_ip(cls, v, info):
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"{info.field_name} must be a valid IPv4 or IPv6 address") from exc
        return v


class AlertSource(str, Enum):
    wazuh = "wazuh"
    zeek = "zeek"


class AgentInfo(BaseModel):
    id: Optional[str] = Field(default=None, max_length=100)
    name: Optional[str] = Field(default=None, max_length=100)
    ip: Optional[str] = Field(default=None, max_length=45)

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v):
        if v is not None:
            ipaddress.ip_address(v)
        return v


class AlertWebhookCreate(BaseModel):
    """Canonical Wazuh/Zeek alert sent to the authenticated webhook."""

    alert_id: str = Field(min_length=1, max_length=200)
    timestamp: datetime
    source: AlertSource
    rule_id: Optional[str] = Field(default=None, max_length=100)
    rule_description: str = Field(min_length=1)
    severity: Optional[int] = Field(default=None, ge=0, le=15, description="Original numeric Wazuh-style level, when provided")
    severity_label: Optional[Severity] = None
    agent: Optional[AgentInfo] = None
    src_ip: Optional[str] = Field(default=None, max_length=45)
    dst_ip: Optional[str] = Field(default=None, max_length=45)
    sensor_ip: Optional[str] = Field(default=None, max_length=45)
    sensor_id: Optional[str] = Field(default=None, max_length=100)
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = Field(default=None, max_length=20)
    status: EventStatus
    raw: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def fix_timestamp(cls, v):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("src_ip", "dst_ip", "sensor_ip")
    @classmethod
    def check_optional_ip(cls, v, info):
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"{info.field_name} must be a valid IPv4 or IPv6 address") from exc
        return v

    @model_validator(mode="after")
    def require_source_severity(self):
        if self.severity is None and self.severity_label is None:
            raise ValueError("provide numeric severity or severity_label")
        if self.source == AlertSource.wazuh and self.severity is None:
            raise ValueError("Wazuh alerts must provide numeric severity")
        if self.severity is not None and self.severity_label is not None:
            level = self.severity
            expected = "low" if level <= 6 else "medium" if level <= 9 else "high" if level <= 12 else "critical"
            if self.severity_label.value != expected:
                raise ValueError("severity_label does not match the numeric severity range")
        return self


class AlertWebhookOut(BaseModel):
    event_id: int
    alert_id: str
    timestamp: datetime
    source: AlertSource
    rule_id: Optional[str] = None
    rule_description: str
    severity: Optional[int] = None
    severity_label: str
    agent: Optional[AgentInfo] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    sensor_ip: Optional[str] = None
    sensor_id: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    status: EventStatus
    raw: Optional[dict[str, Any] | str] = None


class AIAnalysisCreate(BaseModel):
    """Result sent by the AI automation team for an existing event."""

    model_config = ConfigDict(protected_namespaces=())

    event_id: int = Field(gt=0)
    agent_name: str = Field(min_length=1, max_length=100)
    model_version: str = Field(min_length=1, max_length=100)
    severity: Severity
    risk_score: float = Field(ge=0, le=100)
    category: str = Field(min_length=1, max_length=100)
    confidence: float
    explanation: str
    recommended_action: str
    created_at: datetime = Field(default_factory=_now)

    @field_validator("agent_name", "model_version", "category")
    @classmethod
    def trim_required_text(cls, v: str, info):
        value = v.strip()
        if not value:
            raise ValueError(f"{info.field_name} must not be empty")
        return value

    @field_validator("created_at")
    @classmethod
    def fix_created_at(cls, v):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class EventStatusUpdate(BaseModel):
    status: Optional[EventStatus] = None
    disposition: Optional[Disposition] = None

    @model_validator(mode="after")
    def need_something_to_change(self):
        if self.status is None and "disposition" not in self.model_fields_set:
            raise ValueError("send status, disposition, or both")
        return self


class EventSummary(BaseModel):
    """Used in lists - the raw event is left out to keep lists small."""

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    source: str
    source_alert_id: Optional[str] = None
    event_id: int
    alert_id: Optional[str] = None
    event_type: str
    title: Optional[str] = Field(default=None, validate_default=True)
    severity: Optional[int] = Field(default=None, validation_alias="severity_value")
    severity_label: str = Field(validation_alias="severity")
    status: str
    disposition: Optional[str] = None
    description: str
    agent: Optional[AgentInfo] = None
    sensor_ip: Optional[str] = None
    sensor_id: Optional[str] = None
    src_ip: Optional[str] = Field(default=None, validation_alias="source_ip")
    dst_ip: Optional[str] = Field(default=None, validation_alias="destination_ip")
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    zeek_uid: Optional[str] = None
    rule_description: str = Field(validation_alias="description")
    rule_id: Optional[str] = None
    timestamp: datetime
    received_at: datetime
    agent_name: Optional[str] = None
    model_version: Optional[str] = None
    ai_severity_label: Optional[str] = None
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    category: Optional[str] = None
    confidence: Optional[float] = None
    explanation: Optional[str] = None
    recommended_action: Optional[str] = None
    created_at: Optional[datetime] = None

    @field_validator("title")
    @classmethod
    def title_falls_back_to_type(cls, v, info):
        return v or info.data.get("event_type")


class EventOut(EventSummary):
    raw: Optional[dict[str, Any] | str] = Field(default=None, validation_alias="raw_event")

    @field_validator("raw", mode="before")
    @classmethod
    def load_raw_event(cls, v):
        # stored as JSON text in the database, returned as real JSON
        if isinstance(v, str):
            try:
                return json.loads(v)
            except ValueError:
                return v
        return v


class AlertOut(BaseModel):
    """Alert shape requested by the dashboard (an alert is a stored security event)."""

    model_config = ConfigDict(protected_namespaces=())

    id: int
    event_id: int
    alert_id: Optional[str] = None
    title: str
    severity: Optional[int] = None
    severity_label: str
    source: str
    source_alert_id: Optional[str] = None
    status: str
    disposition: Optional[str] = None
    timestamp: datetime
    description: str
    agent: Optional[AgentInfo] = None
    sensor_ip: Optional[str] = None
    sensor_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    zeek_uid: Optional[str] = None
    agent_name: Optional[str] = None
    model_version: Optional[str] = None
    ai_severity_label: Optional[str] = None
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    category: Optional[str] = None
    confidence: Optional[float] = None
    explanation: Optional[str] = None
    recommended_action: Optional[str] = None
    created_at: Optional[datetime] = None


class IngestResult(BaseModel):
    source: str
    ingested: int  # NEW events stored by this request
    ids: list[int]  # ids of the new events
    duplicates: int = 0  # events skipped because the same idempotency key was already stored
    duplicate_ids: list[int] = []  # ids of the rows that already existed
    not_deduplicated: int = 0  # new events stored WITHOUT an idempotency key (origin unknown): a resend is not recognised


# ---------- Dashboard views ----------
class DroneStatus(BaseModel):
    drone_id: str
    status: str  # "online" / "offline" - based on when telemetry last arrived
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    battery_percentage: Optional[int] = None
    flight_mode: Optional[str] = None
    timestamp: datetime
    received_at: datetime


class TrackPoint(BaseModel):
    timestamp: datetime
    latitude: float
    longitude: float
    altitude_m: Optional[float] = None
    battery_percentage: Optional[int] = None


class AlertCounts(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_disposition: dict[str, int]
    new_by_severity: dict[str, int]


class DroneCounts(BaseModel):
    total: int
    online: int
    offline: int


class RiskSummary(BaseModel):
    # Always empty for now: the risk score comes from the AI team, whose format is not agreed yet.
    score: Optional[float] = None
    level: Optional[str] = None
    updated_at: Optional[datetime] = None


class Overview(BaseModel):
    alerts: AlertCounts
    drones: DroneCounts
    risk: RiskSummary


# DroneEventCreate refers to Severity, which is defined further up than the class that uses it
DroneEventCreate.model_rebuild()
DroneEventAccepted.model_rebuild()
