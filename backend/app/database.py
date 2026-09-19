"""SQLAlchemy engine, session factory and declarative base."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings

settings = get_settings()

_render = settings.DATABASE_URL.split(":", 1)[0]
_engine_kwargs: dict = {"pool_pre_ping": True}
if _render in {"sqlite", "sqlite+pysqlite"}:
    # FastAPI serves requests from a threadpool; sqlite needs sharing enabled.
    _engine_kwargs = {"connect_args": {"check_same_thread": False}}

engine = create_engine(settings.DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_tables() -> None:
    """Create tables via metadata when no migration tool is available.

    Used in demo/dev mode (SQLite or inline scans) so the API works out of
    the box. Docker/production uses Alembic on container startup instead.
    """
    from . import models  # noqa: F401  # register table metadata

    Base.metadata.create_all(bind=engine)