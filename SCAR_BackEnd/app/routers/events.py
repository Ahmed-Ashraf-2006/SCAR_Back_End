from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers.common import event_filters
from app.security import require_ai_token, require_security_token, require_token
from app.schemas import AIAnalysisCreate, EventCreate, EventOut, EventStatusUpdate, EventSummary, Page
from app.services import event_service

router = APIRouter(prefix="/api/v1/events", tags=["Security Events"])
ai_router = APIRouter(
    prefix="/api/v1/ai",
    tags=["AI Analysis"],
    dependencies=[Depends(require_ai_token)],
)


@ai_router.post("/analysis", response_model=EventOut)
def receive_ai_analysis(data: AIAnalysisCreate, db: Session = Depends(get_db)):
    """Store an AI result using the event_id provided by the automation team."""
    event = event_service.get_event(db, data.event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event_service.update_ai_analysis(db, event, data)


@router.post("", response_model=EventOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_security_token)])
def create_event(data: EventCreate, response: Response, db: Session = Depends(get_db)):
    """Store an event that is already in the unified format. Raw Zeek/Wazuh events go to /api/v1/ingest/{source}.

    Send an optional `dedup_key`: if that key is already stored, the existing event is returned with 200
    and nothing new is saved.
    """
    event, created = event_service.create_event_idempotent(db, data)
    if not created:
        response.status_code = status.HTTP_200_OK
    return event


@router.get("", response_model=Page[EventSummary])
def list_events(filters: dict = Depends(event_filters), db: Session = Depends(get_db)):
    items, total = event_service.list_events(db, **filters)
    return Page[EventSummary](items=items, total=total)


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.patch("/{event_id}/status", response_model=EventOut, dependencies=[Depends(require_token)])
def change_status(event_id: int, body: EventStatusUpdate, db: Session = Depends(get_db)):
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event_service.update_status_and_disposition(db, event, body)


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_token)])
def delete_event(event_id: int, db: Session = Depends(get_db)):
    event = event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    event_service.delete_event(db, event)
