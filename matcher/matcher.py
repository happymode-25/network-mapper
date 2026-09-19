"""Correlation engine: CVE matching, confidence modelling and risk scoring.

The pipeline is:

1. Filter the candidate CVE list to those affecting the service's product
   (by CPE product key and version window).
2. Assign a confidence label: ``high`` for exact version match, ``medium``
   for a version within a range, ``low`` for product-only matches.
3. Enrich with EPSS and KEV when those are enabled.
4. Compute a composite risk score and final severity label.
"""

import json
from typing import Iterable, List, Optional
from pathlib import Path

from scanner.version_normalizer import is_exact_match, version_in_range
from .cpe_mapper import cpes_match

# Asset importance weights fed into the risk formula.
IMPORTANCE_WEIGHTS = {
    "none": 0.0,
    "low": 1.0,
    "medium": 2.0,
    "high": 3.0,
    "critical": 4.0,
}

_SAMPLE_CVES_PATH = Path(__file__).resolve().parent / "data" / "sample_cves.json"

# CVSS / EPSS / KEV / importance weights (build spec Phase 7).
CVSS_WEIGHT = 0.5
EPSS_WEIGHT = 3.0  # epss * 10 * 0.3
KEV_BONUS = 2.0


def load_sample_cves() -> List[dict]:
    """Load the bundled sample CVE dataset (offline friendly)."""
    with open(_SAMPLE_CVES_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def compute_risk(
    cvss_score: Optional[float],
    epss_score: Optional[float],
    kev: bool,
    asset_importance: str = "low",
) -> float:
    """Compute the composite risk score: ``(cvss*0.5)+(epss*10*0.3)+(kev?2:0)+importance``.

    Result is clamped to the 0.0–10.0 range.
    """
    cvss = float(cvss_score or 0.0)
    epss = float(epss_score or 0.0)
    weight = IMPORTANCE_WEIGHTS.get(asset_importance.lower(), IMPORTANCE_WEIGHTS["low"])
    risk = cvss * CVSS_WEIGHT + epss * 10.0 * EPSS_WEIGHT / 10.0 + (KEV_BONUS if kev else 0.0) + weight
    return round(min(10.0, max(0.0, risk)), 2)


def severity_from_risk(risk: float) -> str:
    """Map a risk score to a severity label (build spec thresholds)."""
    if risk <= 0:
        return "none"
    if risk < 4.0:
        return "low"
    if risk < 7.0:
        return "medium"
    if risk < 9.0:
        return "high"
    return "critical"


def _confidence(service_version: Optional[str], cve: dict, in_range: bool) -> str:
    """Assign high / medium / low confidence for a service-CVE match."""
    if not in_range:
        return "low"
    if is_exact_match(service_version, cve.get("max_version")):
        return "high"
    if cve.get("min_version") or cve.get("max_version"):
        return "medium"
    return "low"


def match_service(
    service: dict,
    cve_list: Iterable[dict],
    use_kev: bool = False,
    use_epss: bool = False,
    asset_importance: str = "low",
) -> List[dict]:
    """Return findings for a service against a candidate CVE list.

    ``service`` is the scanner output dict with keys ``product``, ``version``
    and ``cpe``. Each finding contains all fields persisted to the DB.
    """
    service_cpe = service.get("cpe")
    product = (service.get("product") or "").lower().strip()
    version = service.get("version")
    findings: List[dict] = []

    for cve in cve_list:
        cve_cpe = cve.get("cpe") or ""
        if service_cpe:
            if not cpes_match(service_cpe, cve_cpe):
                continue
        elif product:
            if product not in cve_cpe.lower():
                continue
        else:
            continue

        in_range = version_in_range(
            version,
            cve.get("min_version"),
            cve.get("max_version"),
            min_exclusive=bool(cve.get("min_exclusive")),
            max_exclusive=bool(cve.get("max_exclusive")),
        )
        if not in_range:
            continue

        kev = bool(cve.get("kev")) if use_kev else False
        epss = float(cve.get("epss") or 0.0) if use_epss else 0.0
        cvss = float(cve.get("cvss_v3") or cve.get("cvss_v4") or 0.0)
        risk = compute_risk(cvss, epss, kev, asset_importance)

        findings.append(
            {
                "cve_id": cve.get("cve_id", ""),
                "severity": severity_from_risk(risk),
                "cvss_score": cvss if cvss else None,
                "cvss_vector": cve.get("cvss_vector"),
                "epss_score": epss if use_epss else None,
                "kev": kev,
                "description": cve.get("description"),
                "remediation": cve.get("remediation"),
                "confidence": _confidence(version, cve, in_range),
                "risk_score": risk,
            }
        )
    return findings


def cves_for_sample(product: Optional[str], cve_list: Optional[List[dict]] = None) -> List[dict]:
    """Filter sample CVEs down to those affecting ``product``.

    Raises no exceptions for unknown products — returns an empty list.
    """
    if product is None:
        return []
    candidates = cve_list if cve_list is not None else load_sample_cves()
    product_key = product.lower().strip()
    return [
        cve for cve in candidates if product_key in (cve.get("cpe") or "").lower()
    ]