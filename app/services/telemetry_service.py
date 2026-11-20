import logging

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import TelemetryRecord
from app.schemas import GpsData, TelemetryCreate, TelemetryData, TelemetryOut

logger = logging.getLogger(__name__)


class DuplicatePacketError(Exception):
    """Same drone_id + sequence was already stored."""


def create_telemetry(db: Session, data: TelemetryCreate) -> TelemetryRecord:
    already = (
        db.query(TelemetryRecord.id)
        .filter(
            TelemetryRecord.drone_id == data.drone_id,
            TelemetryRecord.sequence == data.sequence,
        )
        .first()
    )
    if already:
        raise DuplicatePacketError()

    t = data.telemetry
    gps = t.gps
    record = TelemetryRecord(
        drone_id=data.drone_id,
        sequence=data.sequence,
        timestamp=data.timestamp,
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
    logger.info("Telemetry saved drone=%s seq=%s", record.drone_id, record.sequence)
    return record


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
            gps=gps,
        ),
    )


def list_telemetry(db: Session, drone_id: str | None = None, limit: int = 100):
    query = db.query(TelemetryRecord)
    if drone_id:
        query = query.filter(TelemetryRecord.drone_id == drone_id)
    return query.order_by(TelemetryRecord.id.desc()).limit(limit).all()


def get_latest(db: Session, drone_id: str):
    return (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.drone_id == drone_id)
        .order_by(TelemetryRecord.timestamp.desc(), TelemetryRecord.sequence.desc())
        .first()
    )
