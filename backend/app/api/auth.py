"""Authentication endpoints: /api/token."""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from ..config import get_settings
from ..schemas import Token, User
from ..security import authenticate, create_access_token
from .deps import get_current_user

router = APIRouter(prefix="/api", tags=["auth"])
settings = get_settings()


@router.post("/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    """Issue a JWT for the configured admin credential pair."""
    if not authenticate(form.username, form.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        form.username, expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return Token(access_token=token)


@router.get("/me", response_model=User)
def me(username: str = Depends(get_current_user)):
    """Return the current authenticated user."""
    return User(username=username)