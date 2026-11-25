from datetime import datetime
from typing import Optional

from fastapi import Query

from app.schemas import Disposition, EventStatus, Severity


def event_filters(
    severity_label: Optional[Severity] = Query(None, description="low, medium, high, critical"),
    status: Optional[EventStatus] = None,
    disposition: Optional[Disposition] = None,
    source: Optional[str] = Query(None, description="zeek, wazuh, ..."),
    date_from: Optional[datetime] = Query(None, alias="from", description="ISO 8601, e.g. 2026-11-20T00:00:00Z"),
    date_to: Optional[datetime] = Query(None, alias="to", description="ISO 8601"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    """Shared filters + paging for the events and alerts lists."""
    return {
        "severity_label": severity_label.value if severity_label else None,
        "status": status.value if status else None,
        "disposition": disposition.value if disposition else None,
        "source": source,
        "date_from": date_from,
        "date_to": date_to,
        "limit": limit,
        "offset": offset,
    }
