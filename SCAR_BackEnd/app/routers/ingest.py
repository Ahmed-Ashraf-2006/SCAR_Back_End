import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.normalizers import NORMALIZERS, NormalizationError, normalize, supported_sources
from app.schemas import IngestResult
from app.security import require_security_token
from app.services import event_service

logger = logging.getLogger(__name__)

MAX_BATCH = 500

router = APIRouter(
    prefix="/api/v1/ingest",
    tags=["Ingest (raw Zeek / Wazuh)"],
    dependencies=[Depends(require_security_token)],
)


@router.post("/{source}", response_model=IngestResult, status_code=201)
def ingest_raw_events(
    source: str,
    body: Any = Body(..., description="One raw event (JSON object) or a list of raw events, in the ORIGINAL Zeek / Wazuh format"),
    db: Session = Depends(get_db),
):
    """Receive raw events, convert them to the unified format, and store them with the raw event.

    Sending the same event again (retry after a network failure) does not create a second alert: it is
    counted in `duplicates` and the existing id is returned in `duplicate_ids`.
    """
    source = source.strip().lower()
    if source not in NORMALIZERS:
        raise HTTPException(
            status_code=404,
            detail=f"Unsupported source '{source}'. Supported: {', '.join(supported_sources())}",
        )

    raw_events = body if isinstance(body, list) else [body]
    if not raw_events:
        raise HTTPException(status_code=422, detail="No events were sent")
    if len(raw_events) > MAX_BATCH:
        raise HTTPException(status_code=422, detail=f"Too many events in one request (max {MAX_BATCH})")

    unified = []
    for index, raw in enumerate(raw_events):
        try:
            normalized = normalize(source, raw)
            if normalized is not None:
                unified.append(normalized)
        except NormalizationError as exc:
            # nothing is saved if any event is invalid
            raise HTTPException(status_code=422, detail=f"Event #{index}: {exc}")

    try:
        saved, duplicate_ids = event_service.ingest_events(db, unified)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Database error while saving ingested events")
        raise HTTPException(status_code=500, detail="Database error")
    return IngestResult(
        source=source,
        ingested=len(saved),
        ids=[e.id for e in saved],
        duplicates=len(duplicate_ids),
        duplicate_ids=duplicate_ids,
        not_deduplicated=sum(1 for e in saved if e.dedup_key is None),
    )
