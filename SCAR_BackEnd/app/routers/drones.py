import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import DroneStatus, Page, TrackPoint
from app.security import require_token
from app.services import telemetry_service

logger = logging.getLogger(__name__)

# Built from telemetry, so it needs the same Bearer token.
router = APIRouter(prefix="/api/v1/drones", tags=["Drones"], dependencies=[Depends(require_token)])


@router.get("", response_model=Page[DroneStatus])
def list_drones(db: Session = Depends(get_db)):
    """Latest known state of every drone."""
    try:
        records = telemetry_service.latest_per_drone(db)
    except SQLAlchemyError:
        logger.exception("Database error while reading drones")
        raise HTTPException(status_code=500, detail="Database error")
    return Page[DroneStatus](items=[telemetry_service.to_drone_status(r) for r in records], total=len(records))


@router.get("/{drone_id}", response_model=DroneStatus)
def get_drone(drone_id: str, db: Session = Depends(get_db)):
    record = telemetry_service.get_latest(db, drone_id)
    if record is None:
        raise HTTPException(status_code=404, detail="No telemetry found for this drone")
    return telemetry_service.to_drone_status(record)


@router.get("/{drone_id}/track", response_model=Page[TrackPoint])
def get_track(
    drone_id: str,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """GPS path of a drone (only readings that have a position). Newest first."""
    points, total = telemetry_service.track(db, drone_id, limit, offset)
    return Page[TrackPoint](items=points, total=total)
