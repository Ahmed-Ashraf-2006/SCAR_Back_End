import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Drone
from app.schemas import DroneEventAccepted, DroneEventCreate, HealthCreate, HealthOut, TelemetryAccepted
from app.security import ensure_same_drone, require_drone, require_token
from app.services import drone_service

logger = logging.getLogger(__name__)

# Messages a drone sends about itself. Each needs that drone's own token (PROPOSED contract).
router = APIRouter(prefix="/api/v1", tags=["Drone ingest"])


@router.post("/health", response_model=TelemetryAccepted)
def receive_health(data: HealthCreate, db: Session = Depends(get_db), drone: Drone = Depends(require_drone)):
    """System-health message (proposed rate: every 5 s)."""
    ensure_same_drone(drone, data.drone_id)
    try:
        record, gap = drone_service.create_health(db, data)
    except drone_service.DuplicateMessageError:
        raise HTTPException(status_code=409, detail="Duplicate health message (same drone_id, boot_id and sequence)")
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Database error")
    return TelemetryAccepted(drone_id=record.drone_id, sequence=record.sequence, gap=gap)


@router.get("/drones/{drone_id}/health/latest", response_model=HealthOut, dependencies=[Depends(require_token)])
def latest_health(drone_id: str, db: Session = Depends(get_db)):
    record = drone_service.latest_health(db, drone_id)
    if record is None:
        raise HTTPException(status_code=404, detail="No health data found for this drone")
    return drone_service.health_to_out(record)


@router.post("/drone-events", response_model=DroneEventAccepted, status_code=201)
def receive_drone_event(data: DroneEventCreate, db: Session = Depends(get_db), drone: Drone = Depends(require_drone)):
    """Security event detected by the drone itself, sent immediately."""
    ensure_same_drone(drone, data.drone_id)
    try:
        event, gap = drone_service.create_drone_event(db, data)
    except drone_service.DuplicateMessageError:
        raise HTTPException(status_code=409, detail="Duplicate drone event (same sequence or event_uid)")
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Database error")
    return DroneEventAccepted(event_id=event.id, drone_id=data.drone_id, sequence=data.sequence, gap=gap)
