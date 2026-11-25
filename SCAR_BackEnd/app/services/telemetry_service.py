import logging
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import TelemetryRecord
from app.config import ONLINE_WINDOW_SECONDS
from app.services.gaps import find_gap
from app.schemas import GapInfo, DroneStatus, GpsData, TelemetryCreate, TelemetryData, TelemetryOut, TrackPoint

logger = logging.getLogger(__name__)


class DuplicatePacketError(Exception):
    """Same drone_id + sequence was already stored."""


def create_telemetry(db: Session, data: TelemetryCreate) -> tuple[TelemetryRecord, GapInfo | None]:
    already = (
        db.query(TelemetryRecord.id)
        .filter(
            TelemetryRecord.drone_id == data.drone_id,
            TelemetryRecord.boot_id == data.boot_id,
            TelemetryRecord.sequence == data.sequence,
        )
        .first()
    )
    if already:
        raise DuplicatePacketError()
    gap = find_gap(
        db,
        TelemetryRecord.sequence,
        [TelemetryRecord.drone_id == data.drone_id, TelemetryRecord.boot_id == data.boot_id],
        data.sequence,
    )

    t = data.telemetry
    gps = t.gps
    record = TelemetryRecord(
        drone_id=data.drone_id,
        boot_id=data.boot_id,
        schema_version=data.schema_version,
        sequence=data.sequence,
        timestamp=data.timestamp,
        system_status=t.system_status,
        altitude_m=t.altitude_m,
        speed_mps=t.speed_mps,
        roll_deg=t.roll_deg,
        pitch_deg=t.pitch_deg,
        yaw_deg=t.yaw_deg,
        battery_voltage=t.battery_voltage,
        battery_percentage=t.battery_percentage,
        flight_mode=t.flight_mode,
        gps_latitude=gps.latitude if gps else None,
        gps_longitude=gps.longitude if gps else None,
        gps_satellites=gps.satellites if gps else None,
    )
    try:
        db.add(record)
        db.commit()
    except IntegrityError:
        # two identical packets arrived at the same moment
        db.rollback()
        raise DuplicatePacketError()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Database error while saving telemetry")
        raise
    db.refresh(record)
    if gap:
        logger.warning("Telemetry gap drone=%s boot=%s expected=%s got=%s (%s missing)",
                       record.drone_id, record.boot_id, gap.expected_sequence, gap.received_sequence, gap.missing)
    logger.info("Telemetry saved drone=%s seq=%s", record.drone_id, record.sequence)
    return record, gap


def to_out(r: TelemetryRecord) -> TelemetryOut:
    has_gps = any(v is not None for v in (r.gps_latitude, r.gps_longitude, r.gps_satellites))
    gps = (
        GpsData(latitude=r.gps_latitude, longitude=r.gps_longitude, satellites=r.gps_satellites)
        if has_gps
        else None
    )
    return TelemetryOut(
        id=r.id,
        drone_id=r.drone_id,
        schema_version=r.schema_version,
        boot_id=r.boot_id,
        sequence=r.sequence,
        timestamp=r.timestamp,
        received_at=r.received_at,
        telemetry=TelemetryData(
            altitude_m=r.altitude_m,
            speed_mps=r.speed_mps,
            roll_deg=r.roll_deg,
            pitch_deg=r.pitch_deg,
            yaw_deg=r.yaw_deg,
            battery_voltage=r.battery_voltage,
            battery_percentage=r.battery_percentage,
            flight_mode=r.flight_mode,
            system_status=r.system_status,
            gps=gps,
        ),
    )


def list_telemetry(db: Session, drone_id: str | None = None, limit: int = 100, offset: int = 0):
    """Returns (records, total). Newest first."""
    query = db.query(TelemetryRecord)
    if drone_id:
        query = query.filter(TelemetryRecord.drone_id == drone_id)
    total = query.count()
    records = (
        query.order_by(TelemetryRecord.timestamp.desc(), TelemetryRecord.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return records, total


def get_latest(db: Session, drone_id: str):
    return (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.drone_id == drone_id)
        .order_by(TelemetryRecord.timestamp.desc(), TelemetryRecord.sequence.desc())
        .first()
    )


# ---------------- dashboard views ----------------
def is_online(received_at: datetime, now: datetime | None = None) -> bool:
    """Online = telemetry arrived within ONLINE_WINDOW_SECONDS (PROPOSED rule)."""
    now = now or datetime.now(timezone.utc)
    return (now - received_at).total_seconds() <= ONLINE_WINDOW_SECONDS


def to_drone_status(r: TelemetryRecord, now: datetime | None = None) -> DroneStatus:
    return DroneStatus(
        drone_id=r.drone_id,
        status="online" if is_online(r.received_at, now) else "offline",
        latitude=r.gps_latitude,
        longitude=r.gps_longitude,
        altitude_m=r.altitude_m,
        battery_percentage=r.battery_percentage,
        flight_mode=r.flight_mode,
        timestamp=r.timestamp,
        received_at=r.received_at,
    )


def latest_per_drone(db: Session) -> list[TelemetryRecord]:
    drone_ids = [row[0] for row in db.query(TelemetryRecord.drone_id).distinct().order_by(TelemetryRecord.drone_id)]
    latest = [get_latest(db, d) for d in drone_ids]
    return [r for r in latest if r is not None]


def drone_counts(db: Session) -> dict:
    now = datetime.now(timezone.utc)
    records = latest_per_drone(db)
    online = sum(1 for r in records if is_online(r.received_at, now))
    return {"total": len(records), "online": online, "offline": len(records) - online}


def track(db: Session, drone_id: str, limit: int = 500, offset: int = 0):
    """GPS history of one drone. Returns (points, total). Newest first."""
    query = db.query(TelemetryRecord).filter(
        TelemetryRecord.drone_id == drone_id,
        TelemetryRecord.gps_latitude.isnot(None),
        TelemetryRecord.gps_longitude.isnot(None),
    )
    total = query.count()
    rows = (
        query.order_by(TelemetryRecord.timestamp.desc(), TelemetryRecord.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    points = [
        TrackPoint(
            timestamp=r.timestamp,
            latitude=r.gps_latitude,
            longitude=r.gps_longitude,
            altitude_m=r.altitude_m,
            battery_percentage=r.battery_percentage,
        )
        for r in rows
    ]
    return points, total
