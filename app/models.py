from datetime import datetime, timezone

from sqlalchemy import String, Float, Integer, DateTime, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


# Telemetry columns follow the team handoff spec (Abdelrhman).
# Unavailable sensor values are stored as NULL - we never invent readings.
# The table design itself is still to be reviewed with Omar (database).
class TelemetryRecord(Base):
    __tablename__ = "telemetry"
    __table_args__ = (
        UniqueConstraint("drone_id", "sequence", name="uq_drone_sequence"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    drone_id: Mapped[str] = mapped_column(String(50), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    altitude_m: Mapped[float | None] = mapped_column(Float, nullable=True)
    speed_mps: Mapped[float | None] = mapped_column(Float, nullable=True)
    roll_deg: Mapped[float | None] = mapped_column(Float, nullable=True)
    pitch_deg: Mapped[float | None] = mapped_column(Float, nullable=True)
    yaw_deg: Mapped[float | None] = mapped_column(Float, nullable=True)
    battery_voltage: Mapped[float | None] = mapped_column(Float, nullable=True)
    battery_percentage: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flight_mode: Mapped[str | None] = mapped_column(String(50), nullable=True)

    gps_latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    gps_longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    gps_satellites: Mapped[int | None] = mapped_column(Integer, nullable=True)

    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    device_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
