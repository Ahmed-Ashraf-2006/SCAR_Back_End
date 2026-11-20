import logging
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import API_TOKEN

logger = logging.getLogger(__name__)

# auto_error=False so we can return our own 401 (per the team spec)
bearer_scheme = HTTPBearer(auto_error=False)


def require_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    if not API_TOKEN:
        logger.error("API_TOKEN is not set in the environment / .env file")
        raise HTTPException(status_code=500, detail="Server authentication is not configured")

    if credentials is None or not secrets.compare_digest(credentials.credentials, API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )
