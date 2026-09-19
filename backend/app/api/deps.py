"""Shared FastAPI dependencies (authentication)."""

from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from ..security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")


def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """Return the authenticated username for the bearer token."""
    username = decode_access_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


def optional_user(token: Optional[str] = Depends(oauth2_scheme)) -> Optional[str]:
    """Return the username when a valid token is supplied else None."""
    if not token:
        return None
    return decode_access_token(token)