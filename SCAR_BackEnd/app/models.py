from datetime import datetime, timezone

from sqlalchemy import String, Float, Integer, DateTime, Text, UniqueConstraint, Index, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """DateTime that is always stored as UTC and always returned timezone-aware.

    SQLite does not keep timezone information, so without this the API
    returned timestamps without the trailing Z.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


# Telemetry columns follow the team handoff spec (Abdelrhman).
# Unavailable sensor values are stored as NULL - we never invent readings.
# The table design itself is still to be reviewed with Omar (database).
class TelemetryRecord(Base):
    __tablename__ = "telemetry"
    __table_args__ = (
        # boot_id lets a rebooted drone restart its sequence counter without being rejected as a duplicate
        UniqueConstraint("drone_id", "boot_id", "sequence", name="uq_drone_boot_sequence"),
        Index("ix_telemetry_drone_time", "drone_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    drone_id: Mapped[str] = mapped_column(String(50), index=True)
    boot_id: Mapped[str] = mapped_column(String(64), default="0", server_default="0")
    schema_version: Mapped[str] = mapped_column(String(20), default="1.0", server_default="1.0")
    sequence: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime())

    altitude_m: Mapped[float | None] = mapped_column(Float, nullable=True)
    speed_mps: Mapped[float | None] = mapped_column(Float, nullable=True)
    roll_deg: Mapped[float | None] = mapped_column(Float, nullable=True)
    pitch_deg: Mapped[float | None] = mapped_column(Float, nullable=True)
    yaw_deg: Mapped[float | None] = mapped_column(Float, nullable=True)
    battery_voltage: Mapped[float | None] = mapped_column(Float, nullable=True)
    battery_percentage: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flight_mode: Mapped[str | None] = mapped_column(String(50), nullable=True)
    system_status: Mapped[str | None] = mapped_column(String(50), nullable=True)

    gps_latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    gps_longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    gps_satellites: Mapped[int | None] = mapped_column(Integer, nullable=True)

    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source: Mapped[str] = mapped_column(String(100), index=True)  # free text on purpose: new sources need no DB change
    source_alert_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)  # original ID from Zeek/Wazuh
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    severity_value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    device_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    sensor_agent_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    sensor_agent_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    sensor_agent_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    sensor_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    raw_event: Mapped[str | None] = mapped_column(Text, nullable=True)  # original event, stored as JSON text
    status: Mapped[str] = mapped_column(String(20), default="new")
    disposition: Mapped[str | None] = mapped_column(String(30), nullable=True)  # analyst classification, e.g. false_positive; separate from status
    # Normalized network fields (Security change request, section 2). NULL when the source does not provide them.
    sensor_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    zeek_uid: Mapped[str | None] = mapped_column(String(100), nullable=True)  # links records of one connection; NOT a unique event id
    # Idempotency key (section 3): the same key is stored once. NULL = no key could be built, event is not de-duplicated.
    dedup_key: Mapped[str | None] = mapped_column(String(400), nullable=True, unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime())
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    # AI automation analysis is attached to the existing event ID. These are
    # nullable because events may arrive before the AI team has analyzed them.
    agent_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ai_severity_label: Mapped[str | None] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # Events sent by a drone (POST /drone-events). NULL for Wazuh / Zeek events.
    drone_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    boot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    schema_version: Mapped[str | None] = mapped_column(String(20), nullable=True)

    @property
    def event_id(self) -> int:
        return self.id

    @property
    def alert_id(self) -> str | None:
        return self.source_alert_id

    @property
    def agent(self):
        if not any((self.sensor_agent_id, self.sensor_agent_name, self.sensor_agent_ip)):
            return None
        return {
            "id": self.sensor_agent_id,
            "name": self.sensor_agent_name,
            "ip": self.sensor_agent_ip,
        }


class SystemHealth(Base):
    """Drone system-health message (proposed: every 5 s, its own sequence counter)."""

    __tablename__ = "system_health"
    __table_args__ = (
        UniqueConstraint("drone_id", "boot_id", "sequence", name="uq_health_drone_boot_sequence"),
        Index("ix_health_drone_time", "drone_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    drone_id: Mapped[str] = mapped_column(String(50), index=True)
    boot_id: Mapped[str] = mapped_column(String(64), default="0", server_default="0")
    schema_version: Mapped[str] = mapped_column(String(20), default="1.0", server_default="1.0")
    sequence: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime())
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    overall_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_temp_c: Mapped[float | None] = mapped_column(Float, nullable=True)
    storage_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    link_rssi_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)
    uptime_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    components: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON text {"gps": "ok", ...}


class Drone(Base):
    """One row per registered drone. Only the SHA-256 hash of its token is stored."""

    __tablename__ = "drones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    drone_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
