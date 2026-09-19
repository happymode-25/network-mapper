"""Target management endpoints."""

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Asset, Target
from ..schemas import TargetCreate, TargetOut, TargetPage
from ..security import is_allowed, log_audit
from .deps import get_current_user

router = APIRouter(prefix="/api/targets", tags=["targets"])


def _validate_ip(raw: str) -> str:
    """Validate and normalize a target IP address."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid IP address: {raw}",
        ) from None
    return str(addr)


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    """Add a target. Rejected unless the IP is on the ALLOWED_TARGETS allowlist."""
    ip = _validate_ip(payload.ip)
    if not is_allowed(ip):
        log_audit(
            username,
            "target.create",
            target=ip,
            status="denied",
            details="Not on allowlist",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target {ip} is not on the allowed targets list",
        )

    target = Target(ip=ip, hostname=payload.hostname, authorized=True)

    # Auto-link an asset entry so importance can be set for risk scoring.
    asset = db.scalar(
        select(Asset).where(Asset.ip == ip, Asset.hostname == payload.hostname)
    )
    if asset is None and payload.asset_id is not None:
        asset = db.get(Asset, payload.asset_id)
    if asset is None:
        asset = Asset(ip=ip, hostname=payload.hostname)
        db.add(asset)
        db.flush()
    target.asset_id = asset.id

    db.add(target)
    db.commit()
    db.refresh(target)
    log_audit(username, "target.create", target=ip)
    return target


@router.get("", response_model=TargetPage)
def list_targets(
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    """List targets with pagination."""
    page = max(1, page)
    size = min(100, max(1, size))
    total = db.scalar(select(func.count(Target.id))) or 0
    items = db.scalars(
        select(Target).order_by(Target.created_at.desc()).offset((page - 1) * size).limit(size)
    ).all()
    return TargetPage(items=items, total=total, page=page, size=size)


@router.get("/{target_id}", response_model=TargetOut)
def get_target(
    target_id: int,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target