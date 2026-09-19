"""NIST NVD API 2.0 client.

Minimal, rate-limit aware HTTP client for
``https://services.nvd.nist.gov/rest/json/cves/2.0``. Returns normalized
per-CVE dictionaries consumed by :mod:`matcher.matcher`. A local DB cache
(CVE table) is managed by the scan service to reduce API load.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("network_mapper.nvd")

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NO_KEY_DELAY = 6.0  # NVD enforces 5 req / 30s without an API key.
WITH_KEY_DELAY = 0.5  # 50 req / 30s with a key.


class NVDClient:
    """Async client with conservative rate limiting between requests."""

    BASE_URL = BASE_URL

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = BASE_URL,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._delay = WITH_KEY_DELAY if api_key else NO_KEY_DELAY
        self._last_call = 0.0

    async def _request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Rate-limit then perform a GET against the NVD API."""
        elapsed = asyncio.get_event_loop().time() - self._last_call
        if elapsed < self._delay:
            await asyncio.sleep(self._delay - elapsed)
        self._last_call = asyncio.get_event_loop().time()

        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = await self._client.get(self.base_url, params=params, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def get_cves_by_cpe(self, cpe: str, results_per_page: int = 200) -> List[dict]:
        """Fetch CVEs affecting the full ``cpeName`` (version-aware via NVD)."""
        data = await self._request(
            {"cpeName": cpe, "resultsPerPage": results_per_page, "noRejected": "true"}
        )
        return [parse_nvd_cve(item) for item in data.get("vulnerabilities", [])]

    async def search_by_product(self, keyword: str, results_per_page: int = 100) -> List[dict]:
        """Fetch CVEs whose description mentions ``keyword`` (fallback search)."""
        data = await self._request(
            {
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page,
                "noRejected": "true",
            }
        )
        return [parse_nvd_cve(item) for item in data.get("vulnerabilities", [])]

    async def get_cve(self, cve_id: str) -> Optional[dict]:
        """Fetch a single CVE by ID; returns None when not found."""
        try:
            data = await self._request({"cveId": cve_id})
            items = data.get("vulnerabilities", [])
            return parse_nvd_cve(items[0]) if items else None
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def aclose(self) -> None:
        await self._client.aclose()


def parse_nvd_cve(item: dict) -> dict:
    """Normalize a raw NVD API ``vulnerabilities[0]`` item.

    Returns a dict shaped for :func:`matcher.matcher.match_service`:

    ``{cve_id, description, cvss_v3, cvss_v4, severity, cvss_vector, cpe,
       min_version, max_version, published, last_modified, remediation}``
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    metrics = cve.get("metrics", {}) or {}
    cvss_v3 = None
    cvss_v4 = None
    severity = None
    vector = None
    for entry in metrics.get("cvssMetricV31", []) or []:
        data = entry.get("cvssData", {})
        cvss_v3 = data.get("baseScore")
        vector = data.get("vectorString")
        severity = data.get("baseSeverity")
        break
    if cvss_v3 is None:
        for entry in metrics.get("cvssMetricV30", []) or []:
            data = entry.get("cvssData", {})
            cvss_v3 = data.get("baseScore")
        if cvss_v3 is None:
            for entry in metrics.get("cvssMetricV2", []) or []:
                data = entry.get("cvssData", {})
                cvss_v3 = data.get("baseScore")
                if severity is None:
                    severity = data.get("baseSeverity")
    if cvss_v4 is None:
        for entry in metrics.get("cvssMetricV40", []) or []:
            data = entry.get("cvssData", {})
            cvss_v4 = data.get("baseScore")

    weak = cve.get("weaknesses", []) or []
    mitigation = _cve_mitigation(weak)

    configs = cve.get("configurations", []) or []
    cpe = None
    min_version = None
    max_version = None
    min_exclusive = False
    max_exclusive = False
    for cfg in configs:
        nodes = cfg.get("nodes", []) or []
        for node in nodes:
            for match in node.get("cpe_match", []) or []:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5 and cpe is None:
                    cpe = ":".join(parts[:5])
                # Version bounds can appear on any cpe_match; scan them all
                # (NVD puts ranges on the matching criterion itself).
                if match.get("versionEndExcluding") is not None:
                    max_version = match.get("versionEndExcluding")
                    max_exclusive = True
                elif match.get("versionEndIncluding") is not None:
                    max_version = match.get("versionEndIncluding")
                    max_exclusive = False
                if match.get("versionStartExcluding") is not None:
                    min_version = match.get("versionStartExcluding")
                    min_exclusive = True
                elif match.get("versionStartIncluding") is not None:
                    min_version = match.get("versionStartIncluding")
                    min_exclusive = False

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_v3": float(cvss_v3) if cvss_v3 is not None else None,
        "cvss_v4": float(cvss_v4) if cvss_v4 is not None else None,
        "severity": severity,
        "cvss_vector": vector,
        "cpe": cpe,
        "min_version": min_version,
        "max_version": max_version,
        "min_exclusive": min_exclusive,
        "max_exclusive": max_exclusive,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "remediation": mitigation,
    }


def _cve_mitigation(weaknesses: List[dict]) -> str:
    for weakness in weaknesses:
        for desc in weakness.get("description", []) or []:
            return f"CWE reference: {desc.get('value', '')}"
    return "Apply vendor patches or upgrade to a non-affected version."