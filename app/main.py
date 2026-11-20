import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import models  # noqa: F401  (needed so tables are registered)
from app.config import APP_NAME, LOG_LEVEL
from app.database import Base, engine
from app.routers import health, telemetry, events

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ready")
    yield


app = FastAPI(
    title=APP_NAME,
    description="Backend for SCAR - Smart Cybersecurity Autonomous Response Drone",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(telemetry.router)
app.include_router(events.router)
