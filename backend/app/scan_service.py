"""End-to-end scan orchestration.

``execute_scan`` runs the full pipeline in one flow (called from the Celery
worker or directly by tests):

1. Re-validate the target against the allowlist.
2. Asynchronously scan default ports and grab banners.
3. Detect services and normalize versions.
4. Map products to CPE names.
5. Correlate with CVE intelligence (sample data or live NVD/KEV/EPSS).
6. Compute risk-based findings and persist ports/services/findings.
"""

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from matcher import matcher as matcher_mod
from matcher.cpe_mapper import map_to_cpe
from matcher.epss_client import EPSSClient
from matcher.kev_client import KEVClient
from matcher.nvd_client import NVDClient
from scanner import fingerprint, nmap_probe, scanner
from scanner.version_normalizer import normalize_version

from .config import get_settings
from .models import Asset, CVE, Finding, Port, Scan, Service, Target, utcnow
from .security import is_allowed

logger = logging.getLogger("network_mapper.scan_service")

settings = get_settings()


def _asset_importance(db: Session, target: Target) -> str:
    if target.asset_id is None:
        return "low"
    asset = db.get(Asset, target.asset_id)
    return (asset.importance if asset else "low") or "low"


def _cache_cve(db: Session, candidate: dict) -> None:
    """Upsert a CVE row so repeat matches hit the local cache instead of NVD."""
    cve_id = candidate.get("cve_id")
    if not cve_id:
        return
    row = db.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if row is None:
        db.add(
            CVE(
                cve_id=cve_id,
                description=candidate.get("description"),
                cvss_v3=candidate.get("cvss_v3"),
                cvss_v4=candidate.get("cvss_v4"),
                severity=candidate.get("severity"),
            )
        )


def _suggest_ports(target: Target) -> list[int]:
    ports = scanner.default_scan_ports()
    return ports[: settings.MAX_PORTS_PER_SCAN]


def _resolve_scan_ports(scan: Scan, target: Target) -> list[int]:
    """Return the ports to probe: the scan's requested ports or the defaults."""
    if scan.requested_ports:
        try:
            ports = [
                int(token)
                for token in scan.requested_ports.split(",")
                if token.strip().isdigit()
            ]
        except ValueError:  # pragma: no cover - validated at creation time
            ports = []
        if ports:
            return sorted(set(ports))
    return _suggest_ports(target)


async def _persist_services(
    db: Session, scan: Scan, services: list[dict], asset_importance: str
) -> None:
    """Persist open ports, detected services and matched findings per port."""
    source_cves = (
        matcher_mod.load_sample_cves()
        if settings.USE_SAMPLE_CVES
        else None
    )
    logger.info("Persisting %d discovered services for scan %d", len(services), scan.id)

    for svc in services:
        product = svc.get("product")
        raw_version = svc.get("version")
        version = normalize_version(raw_version) if raw_version else None
        svc["version"] = version
        svc["cpe"] = map_to_cpe(product, version)

        if source_cves is not None:
            candidates = matcher_mod.cves_for_sample(product, source_cves)
        else:  # pragma: no cover - exercised only in live-data mode
            candidates = await _live_candidates(svc)

        findings = matcher_mod.match_service(
            svc,
            candidates,
            use_kev=True,
            use_epss=True,
            asset_importance=asset_importance,
        )
        _save_service(db, scan, svc, findings)


def _save_service(
    db: Session, scan: Scan, svc: dict, findings: list[dict]
) -> None:
    port = Port(
        scan_id=scan.id,
        port=svc["port"],
        protocol="tcp",
        state="open",
    )
    db.add(port)
    db.flush()

    service = Service(
        port_id=port.id,
        name=svc.get("name", "unknown"),
        product=svc.get("product"),
        version=svc.get("version"),
        banner=svc.get("banner"),
        cpe=svc.get("cpe"),
    )
    db.add(service)
    db.flush()

    for finding in findings:
        _cache_cve(db, finding)
        row = Finding(
            scan_id=scan.id,
            service_id=service.id,
            cve_id=finding["cve_id"],
            severity=finding["severity"],
            cvss_score=finding.get("cvss_score"),
            cvss_vector=finding.get("cvss_vector"),
            epss_score=finding.get("epss_score"),
            kev=finding.get("kev", False),
            description=finding.get("description"),
            remediation=finding.get("remediation"),
            confidence=finding.get("confidence", "low"),
            risk_score=finding.get("risk_score"),
        )
        db.add(row)


async def _live_candidates(svc: dict) -> list[dict]:
    """Fetch candidate CVEs from NVD for one service (live-data mode)."""
    nvd = NVDClient(api_key=settings.NVD_API_KEY)
    kev = KEVClient()
    epss = EPSSClient()
    candidates: list[dict] = []
    try:
        if svc.get("cpe"):
            candidates = await nvd.get_cves_by_cpe(svc["cpe"])
        elif svc.get("product"):
            candidates = await nvd.search_by_product(svc["product"])
        ids = [c["cve_id"] for c in candidates if c.get("cve_id")]
        if ids:
            epss_map = await epss.get_scores(ids)
            for c in candidates:
                c["epss"] = epss_map.get(c["cve_id"], {}).get("score", 0.0)
                c["kev"] = await kev.is_kev(c["cve_id"])
    finally:
        await nvd.aclose()
        await kev.aclose()
        await epss.aclose()
    return candidates


async def _scan_async(db: Session, scan: Scan, target: Target) -> None:
    ports = _resolve_scan_ports(scan, target)
    services = await scanner.scan_host_with_services(
        target.ip,
        ports,
        timeout=settings.SCAN_PORT_TIMEOUT,
        concurrency=settings.SCAN_CONCURRENCY,
    )
    # Active fingerprinting: identify bannerless services (HTTPS, SMB, ...).
    if settings.FINGERPRINT_PROBE:
        services = await fingerprint.enrich_services(
            target.ip,
            services,
            timeout=settings.FINGERPRINT_TIMEOUT,
        )

    # Optional Nmap -sV: deeper product/version detection when it is installed.
    if settings.USE_NMAP and nmap_probe.nmap_available(settings.NMAP_BINARY):
        open_ports = [s["port"] for s in services]
        if open_ports:
            nmap_results = await asyncio.to_thread(
                nmap_probe.run_nmap_sv,
                settings.NMAP_BINARY,
                target.ip,
                open_ports,
                settings.NMAP_TIMEOUT,
            )
            services = nmap_probe.merge_nmap_results(services, nmap_results)

    importance = _asset_importance(db, target)
    await _persist_services(db, scan, services, importance)


def execute_scan(db: Session, scan_id: int) -> Scan:
    """Run the full scan pipeline for ``scan_id``; returns the persisted Scan."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")
    target = db.get(Target, scan.target_id)
    if target is None:
        scan.status = "failed"
        scan.error = "Target no longer exists"
        scan.finished_at = utcnow()
        db.commit()
        return scan

    scan.status = "running"
    scan.started_at = utcnow()
    scan.error = None
    db.commit()

    try:
        if not is_allowed(target.ip):
            raise PermissionError(
                f"Target {target.ip} is not on the allowed targets list"
            )
        asyncio.run(_scan_async(db, scan, target))
        scan.status = "completed"
        logger.info("Scan %d completed for %s", scan.id, target.ip)
    except Exception as exc:  # noqa: BLE001 - persist any failure reason
        scan.status = "failed"
        scan.error = str(exc)[:2000]
        logger.exception("Scan %d failed for %s", scan.id, target.ip)
    finally:
        scan.finished_at = utcnow()
        db.commit()
        db.refresh(scan)
    return scan