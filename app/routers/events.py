from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import EventCreate, EventOut, EventStatusUpdate, Severity, EventStatus
from app.services import event_service

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.post("/", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def create_event(data: EventCreate, db: Session = Depends(get_db)):
    return event_service.create_event(db, data)


@router.get("/", response_model=list[EventOut])
def list_events(
    severity: Optional[Severity] = None,
    status_filter: Optional[EventStatus] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    return event_service.list_events(
        db,
        severity.value if severity else None,
        status_filter.value if status_filter else None,
        limit,
    )


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.patch("/{event_id}/status", response_model=EventOut)
def change_status(event_id: int, body: EventStatusUpdate, db: Session = Depends(get_db)):
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event_service.update_status(db, event, body.status)


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_event(event_id: int, db: Session = Depends(get_db)):
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    event_service.delete_event(db, event)
