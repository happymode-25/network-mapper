"""Asset management endpoints (importance feeds risk scoring)."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Asset
from ..schemas import AssetCreate, AssetOut, AssetPage, AssetUpdate
from .deps import get_current_user

router = APIRouter(prefix="/api/assets", tags=["assets"])

VALID_IMPORTANCE = {"none", "low", "medium", "high", "critical"}


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    if payload.importance.lower() not in VALID_IMPORTANCE:
        raise HTTPException(status_code=422, detail="Invalid importance value")
    asset = Asset(
        ip=payload.ip,
        hostname=payload.hostname,
        importance=payload.importance.lower(),
        owner=payload.owner,
        tags=payload.tags,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("", response_model=AssetPage)
def list_assets(
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    page = max(1, page)
    size = min(100, max(1, size))
    total = db.scalar(select(func.count(Asset.id))) or 0
    items = db.scalars(
        select(Asset).order_by(Asset.id.desc()).offset((page - 1) * size).limit(size)
    ).all()
    return AssetPage(items=items, total=total, page=page, size=size)


@router.put("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if payload.importance is not None:
        if payload.importance.lower() not in VALID_IMPORTANCE:
            raise HTTPException(status_code=422, detail="Invalid importance value")
        asset.importance = payload.importance.lower()
    if payload.owner is not None:
        asset.owner = payload.owner
    if payload.tags is not None:
        asset.tags = payload.tags
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset