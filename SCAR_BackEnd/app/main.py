import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models  # noqa: F401  (needed so tables are registered)
from app.config import APP_NAME, CORS_ORIGINS, LOG_LEVEL
from app.database import Base, engine
from app.migrations import upgrade_security_event_columns, upgrade_telemetry_table
from app.routers import alerts, drone_ingest, drones, events, health, ingest, overview, telemetry

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    upgrade_security_event_columns(engine)
    upgrade_telemetry_table(engine)
    logger.info("Database tables ready")
    yield


app = FastAPI(
    title=APP_NAME,
    description="Backend for SCAR - Smart Cybersecurity Autonomous Response Drone",
    version="0.1.0",
    lifespan=lifespan,
)

# lets the React dashboard (a different address) call this API from the browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(health.router)
app.include_router(telemetry.router)
app.include_router(events.router)
app.include_router(events.ai_router)
app.include_router(alerts.router)
app.include_router(ingest.router)
app.include_router(drones.router)
app.include_router(drone_ingest.router)
app.include_router(overview.router)
