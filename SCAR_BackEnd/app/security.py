import hashlib
import logging
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app import config
from app.database import get_db
from app.models import Drone

logger = logging.getLogger(__name__)

# auto_error=False so we can return our own 401 (per the team spec)
bearer_scheme = HTTPBearer(auto_error=False)


def hash_token(token: str) -> str:
    """Drone tokens are long random strings, so a plain SHA-256 is enough (no password-style stretching needed)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _unauthorized():
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _check_static(credentials: Optional[HTTPAuthorizationCredentials], expected: str, env_name: str):
    if not expected:
        logger.error("%s is not set in the environment / .env file", env_name)
        raise HTTPException(status_code=500, detail="Server authentication is not configured")
    if credentials is None or not secrets.compare_digest(credentials.credentials, expected):
        raise _unauthorized()


def require_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    """Dashboard / administrator token (API_TOKEN)."""
    _check_static(credentials, config.API_TOKEN, "API_TOKEN")


def require_security_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    """Security team token: Wazuh / Zeek webhook, raw ingest, unified event create."""
    _check_static(credentials, config.SECURITY_TOKEN, "SECURITY_TOKEN")


def require_ai_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    """Internal token for the AI automation endpoint."""
    _check_static(credentials, config.AI_TOKEN, "AI_TOKEN")


def require_drone(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Drone:
    """Per-drone token. Returns the drone the token belongs to; revoked drones are rejected."""
    if credentials is None:
        raise _unauthorized()
    digest = hash_token(credentials.credentials)
    drone = db.query(Drone).filter(Drone.token_hash == digest).first()
    if drone is None or not drone.active:
        raise _unauthorized()
    return drone


def ensure_same_drone(drone: Drone, drone_id: str) -> None:
    """A drone token may only write data for its own drone_id."""
    if drone.drone_id != drone_id:
        raise HTTPException(status_code=403, detail="Token does not belong to this drone_id")
