"""Scan lifecycle and findings endpoints."""

import time
from collections import defaultdict, deque
from typing import DefaultDict, Deque, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .. import exporters, models, schemas
from ..config import get_settings
from ..database import get_db
from ..security import log_audit
from ..tasks import enqueue_scan

router = APIRouter(prefix="/api", tags=["scans"])
settings = get_settings()

# Sliding-window rate limiter: the demo is open-access, so all requests share
# a single "guest" bucket.
_scan_times: DefaultDict[str, Deque[float]] = defaultdict(deque)


def _check_rate_limit() -> None:
    now = time.time()
    window: Deque[float] = _scan_times["guest"]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= settings.RATE_LIMIT_SCANS_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: max {settings.RATE_LIMIT_SCANS_PER_MINUTE} scans/minute",
        )
    window.append(now)


def _parse_requested_ports(raw: Optional[str]) -> Optional[str]:
    """Parse ``ports_to_scan`` into a canonical comma-separated list.

    Accepts ports and inclusive ranges (``22,80-82,443``). Returns ``None``
    when empty so the worker falls back to the default port list.
    """
    if not raw or not raw.strip():
        return None
    ports: set[int] = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_s, _, end_s = token.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise HTTPException(422, detail=f"Invalid port range: {token}") from None
            if not (1 <= start <= end <= 65535):
                raise HTTPException(422, detail=f"Invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit() or not (1 <= int(token) <= 65535):
                raise HTTPException(422, detail=f"Invalid port: {token}")
            ports.add(int(token))
    if len(ports) > 10000:
        raise HTTPException(
            422, detail="Too many ports requested (max 10,000 per scan)"
        )
    return ",".join(str(p) for p in sorted(ports))


def _load_scan(db: Session, scan_id: int) -> models.Scan:
    scan = db.scalar(
        select(models.Scan)
        .where(models.Scan.id == scan_id)
        .options(
            selectinload(models.Scan.target),
            selectinload(models.Scan.ports).selectinload(models.Port.service),
            selectinload(models.Scan.findings),
        )
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/scans", response_model=schemas.ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: schemas.ScanCreate,
    response: Response,
    db: Session = Depends(get_db),
):
    """Queue a scan for an authorized target."""
    _check_rate_limit()
    target = db.get(models.Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.authorized or not _ip_allowed(target.ip):
        raise HTTPException(status_code=400, detail="Target is not authorized for scanning")

    requested_ports = _parse_requested_ports(payload.ports_to_scan)
    scan = models.Scan(
        target_id=target.id,
        status="queued",
        requested_ports=requested_ports,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        enqueue_scan(scan.id)
        log_audit("guest", "scan.create", target=target.ip, status="ok")
        response.status_code = status.HTTP_201_CREATED
    except Exception as exc:  # pragma: no cover - broker may be down in dev/test
        scan.status = "failed"
        scan.error = f"Failed to enqueue: {exc}"
        db.add(scan)
        db.commit()
        log_audit("guest", "scan.create", target=target.ip, status="failed", details=str(exc))
        raise HTTPException(status_code=503, detail=f"Could not enqueue scan: {exc}") from exc

    return scan


def _ip_allowed(ip: str) -> bool:
    from ..security import is_allowed

    return is_allowed(ip)


@router.get("/scans", response_model=schemas.ScanPage)
def list_scans(
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
):
    """List scans with pagination."""
    page = max(1, page)
    size = min(100, max(1, size))
    total = db.scalar(select(func.count(models.Scan.id))) or 0
    items = db.scalars(
        select(models.Scan)
        .order_by(models.Scan.id.desc())
        .offset((page - 1) * size)
        .limit(size)
    ).all()
    return schemas.ScanPage(items=items, total=total, page=page, size=size)


@router.get("/scans/{scan_id}", response_model=schemas.ScanDetail)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """Return a scan with its target, ports, services and findings."""
    scan = _load_scan(db, scan_id)
    return schemas.ScanDetail(
        id=scan.id,
        status=scan.status,
        requested_ports=scan.requested_ports,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error=scan.error,
        target=scan.target,
        ports=scan.ports,
        findings=scan.findings,
    )


@router.get("/scans/{scan_id}/findings", response_model=schemas.FindingPage)
def get_findings(
    scan_id: int,
    page: int = 1,
    size: int = 50,
    severity: str | None = None,
    db: Session = Depends(get_db),
):
    """List findings for a scan, optionally filtered by severity."""
    page = max(1, page)
    size = min(200, max(1, size))
    base = select(models.Finding).where(models.Finding.scan_id == scan_id)
    count_q = select(func.count(models.Finding.id)).where(models.Finding.scan_id == scan_id)
    if severity:
        base = base.where(models.Finding.severity == severity.lower())
        count_q = count_q.where(models.Finding.severity == severity.lower())
    total = db.scalar(count_q) or 0
    items = db.scalars(
        base.order_by(models.Finding.risk_score.desc()).offset((page - 1) * size).limit(size)
    ).all()
    return schemas.FindingPage(items=items, total=total, page=page, size=size)


@router.get("/scans/{scan_id}/export")
def export_scan(
    scan_id: int,
    format: str = Query("json", pattern="^(json|csv|stix)$"),
    db: Session = Depends(get_db),
):
    """Export a scan's findings as JSON, CSV, or a STIX 2.1 bundle."""
    scan = _load_scan(db, scan_id)
    findings = list(scan.findings)

    if format == "csv":
        content = "\ufeff" + exporters.to_csv(scan, findings)
        media_type = "text/csv"
        filename = f"scan-{scan_id}-findings.csv"
    elif format == "stix":
        content = exporters.to_stix(scan, findings)
        media_type = "application/json"
        filename = f"scan-{scan_id}.stix2.json"
    else:
        content = exporters.to_json(scan, findings)
        media_type = "application/json"
        filename = f"scan-{scan_id}.json"

    log_audit("guest", "scan.export", target=scan.target.ip, status="ok", details=f"format={format}")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _compare_item(row: models.Finding) -> dict:
    service = row.service
    return {
        "cve_id": row.cve_id,
        "severity": row.severity,
        "risk_score": row.risk_score,
        "confidence": row.confidence,
        "service": service.name if service else None,
        "version": service.version if service else None,
    }


@router.get("/compare", response_model=schemas.CompareResult)
def compare_scans(
    scan_a: int,
    scan_b: int,
    db: Session = Depends(get_db),
):
    """Diff the findings of two scans: added / removed / changed."""
    scan_a_row = _load_scan(db, scan_a)
    scan_b_row = _load_scan(db, scan_b)
    if scan_a_row.status != "completed" or scan_b_row.status != "completed":
        raise HTTPException(status_code=400, detail="Both scans must be completed")

    a = {f.cve_id: f for f in scan_a_row.findings}
    b = {f.cve_id: f for f in scan_b_row.findings}

    added = [_compare_item(b[k]) for k in b if k not in a]
    removed = [_compare_item(a[k]) for k in a if k not in b]
    changed = [
        _compare_item(b[k])
        for k in a.keys() & b.keys()
        if (a[k].risk_score or 0) != (b[k].risk_score or 0)
        or a[k].severity != b[k].severity
    ]

    return schemas.CompareResult(
        added=added,
        removed=removed,
        changed=changed,
        added_count=len(added),
        removed_count=len(removed),
        changed_count=len(changed),
    )