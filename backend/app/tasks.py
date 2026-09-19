"""Celery application and the ``run_scan`` background task."""

import logging

from celery import Celery

from .config import get_settings

logger = logging.getLogger("network_mapper.tasks")

settings = get_settings()

celery_app = Celery(
    "network_mapper",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Local/demo mode: run tasks synchronously in-process, no broker needed.
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER or settings.INLINE_SCANS,
    task_eager_propagates=True,
)


@celery_app.task(name="network_mapper.run_scan")
def run_scan(scan_id: int) -> None:
    """Execute a full scan (discovery -> detection -> correlation -> persist)."""
    from .database import SessionLocal
    from .scan_service import execute_scan

    db = SessionLocal()
    try:
        execute_scan(db, scan_id)
    except Exception:  # pragma: no cover - defensive; execute_scan handles failures
        logger.exception("Unhandled error running scan %s", scan_id)
    finally:
        db.close()


def enqueue_scan(scan_id: int) -> None:
    """Push a scan onto the Celery queue (one indirection point for tests)."""
    run_scan.delay(scan_id)