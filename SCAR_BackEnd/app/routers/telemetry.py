import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import Page, TelemetryAccepted, TelemetryCreate, TelemetryOut
from app.models import Drone
from app.security import ensure_same_drone, require_drone, require_token
from app.services import telemetry_service

logger = logging.getLogger(__name__)

# Writes need the drone's own token; reads need the dashboard token (API_TOKEN).
router = APIRouter(prefix="/api/v1/telemetry", tags=["Telemetry"])


@router.post("", response_model=TelemetryAccepted, status_code=200)
def receive_telemetry(data: TelemetryCreate, db: Session = Depends(get_db), drone: Drone = Depends(require_drone)):
    ensure_same_drone(drone, data.drone_id)
    try:
        record, gap = telemetry_service.create_telemetry(db, data)
    except telemetry_service.DuplicatePacketError:
        # 409 is a PROPOSAL - the spec does not define a duplicate status yet
        raise HTTPException(status_code=409, detail="Duplicate packet (same drone_id, boot_id and sequence)")
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Database error")
    return TelemetryAccepted(drone_id=record.drone_id, sequence=record.sequence, gap=gap)


@router.get("", response_model=Page[TelemetryOut], dependencies=[Depends(require_token)])
def get_telemetry(
    drone_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    try:
        records, total = telemetry_service.list_telemetry(db, drone_id, limit, offset)
    except SQLAlchemyError:
        logger.exception("Database error while reading telemetry")
        raise HTTPException(status_code=500, detail="Database error")
    return Page[TelemetryOut](items=[telemetry_service.to_out(r) for r in records], total=total)


@router.get("/{drone_id}/latest", response_model=TelemetryOut, dependencies=[Depends(require_token)])
def get_latest_telemetry(drone_id: str, db: Session = Depends(get_db)):
    try:
        record = telemetry_service.get_latest(db, drone_id)
    except SQLAlchemyError:
        logger.exception("Database error while reading telemetry")
        raise HTTPException(status_code=500, detail="Database error")
    if record is None:
        raise HTTPException(status_code=404, detail="No telemetry found for this drone")
    return telemetry_service.to_out(record)
