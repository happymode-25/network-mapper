"""Seed script.

Adds ``127.0.0.1`` as an authorized target (if any), creates an asset with
medium importance, queues an initial scan via Celery and prints confirmation.

Run from the repo root:

    python -m backend.app.seed
"""

import logging

from sqlalchemy import select

from .config import get_settings
from .database import SessionLocal
from .models import Asset, Scan, Target
from .security import is_allowed
from .tasks import enqueue_scan

logger = logging.getLogger("network_mapper.seed")

LOCALHOST_IP = "127.0.0.1"


def seed() -> None:
    """Create the localhost target + asset and queue a scan."""
    get_settings()
    db = SessionLocal()
    try:
        ip = LOCALHOST_IP
        target = db.scalar(select(Target).where(Target.ip == ip))
        if target is None:
            asset = db.scalar(select(Asset).where(Asset.ip == ip))
            if asset is None:
                asset = Asset(ip=ip, hostname="localhost", importance="medium", owner="ops")
                db.add(asset)
                db.flush()
            authorized = is_allowed(ip)
            target = Target(
                ip=ip, hostname="localhost", authorized=authorized, asset_id=asset.id
            )
            db.add(target)
            db.commit()
            db.refresh(target)
            print(f"Added target {ip} (authorized={authorized})")
        else:
            print(f"Target {ip} already exists (authorized={target.authorized})")

        scan = Scan(target_id=target.id, status="queued")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        enqueue_scan(scan.id)
        print(f"Queued scan #{scan.id} for {target.ip}")
    finally:
        db.close()


if __name__ == "__main__":
    seed()