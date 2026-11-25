from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import Overview, RiskSummary
from app.services import event_service, telemetry_service

router = APIRouter(prefix="/api/v1/overview", tags=["Overview"])


@router.get("", response_model=Overview)
def get_overview(db: Session = Depends(get_db)):
    return Overview(
        alerts=event_service.alert_counts(db),
        drones=telemetry_service.drone_counts(db),
        risk=RiskSummary(),  # empty until the AI team results are integrated
    )
