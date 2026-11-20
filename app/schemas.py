import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _now():
    return datetime.now(timezone.utc)


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
    gps: Optional[GpsData] = None


class TelemetryCreate(BaseModel):
    drone_id: str = Field(min_length=1, max_length=50)
    timestamp: datetime
    sequence: int = Field(ge=0)
    telemetry: TelemetryData

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


class TelemetryAccepted(BaseModel):
    status: str = "accepted"
    drone_id: str
    sequence: int


class TelemetryOut(BaseModel):
    id: int
    drone_id: str
    sequence: int
    timestamp: datetime
    received_at: datetime
    telemetry: TelemetryData


# ---------- Security events (proposed format - confirm with security team) ----------
class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EventStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    resolved = "resolved"


class EventCreate(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    severity: Severity
    description: str = ""
    device_ip: Optional[str] = Field(default=None, max_length=45)
    timestamp: datetime = Field(default_factory=_now)

    @field_validator("timestamp")
    @classmethod
    def fix_timestamp(cls, v):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


    @field_validator("device_ip")
    @classmethod
    def check_ip(cls, v):
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("device_ip must be a valid IPv4 or IPv6 address")
        return v


class EventStatusUpdate(BaseModel):
    status: EventStatus


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    event_type: str
    severity: str
    description: str
    device_ip: Optional[str]
    status: str
    timestamp: datetime
    received_at: datetime
