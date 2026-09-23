"""FastAPI application entrypoint.

Run with:

    uvicorn backend.app.main:app --reload
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import assets, scans, targets
from .config import get_settings
from .database import ensure_tables

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("network_mapper")

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Demo/dev convenience: with SQLite or inline scans the app creates its
    # schema directly. Docker/production uses Alembic on container startup.
    if settings.DATABASE_URL.startswith("sqlite") or settings.INLINE_SCANS:
        ensure_tables()
    yield


app = FastAPI(
    title="Network Mapper",
    description="Automated network service discovery and vulnerability assessment platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "https://happymode-25.github.io",  # GitHub Pages-hosted frontend
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(assets.router)


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Liveness probe used by Docker healthchecks."""
    return {"status": "ok", "service": "network-mapper-api"}