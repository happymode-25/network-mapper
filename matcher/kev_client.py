"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

Downloads the official KEV feed, caches it in memory with a TTL, and provides
an ``is_kev(cve_id)`` lookup used to escalate risk on actively exploited CVEs.
"""

import json
import logging
import time
from typing import Dict, Optional

import httpx

logger = logging.getLogger("network_mapper.kev")

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
DEFAULT_TTL = 6 * 3600  # refresh the catalog every 6 hours


class KEVClient:
    """Client for the CISA KEV catalog with in-memory caching."""

    KEV_URL = KEV_URL
    DEFAULT_TTL = DEFAULT_TTL

    def __init__(
        self,
        url: str = KEV_URL,
        ttl: int = DEFAULT_TTL,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.url = url
        self.ttl = ttl
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._cve_ids: Dict[str, dict] = {}
        self._fetched_at = 0.0

    async def _refresh(self) -> None:
        if time.time() - self._fetched_at < self.ttl and self._cve_ids:
            return
        try:
            resp = await self._client.get(self.url)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", []) or []
            self._cve_ids = {
                item.get("cveID"): item
                for item in vulns
                if item.get("cveID")
            }
            self._fetched_at = time.time()
            logger.info("Loaded %d KEV entries", len(self._cve_ids))
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.warning("Failed to refresh KEV catalog: %s", exc)

    async def is_kev(self, cve_id: str) -> bool:
        """Return True when ``cve_id`` is in the KEV catalog."""
        await self._refresh()
        return cve_id in self._cve_ids

    async def kev_entry(self, cve_id: str) -> Optional[dict]:
        """Return the KEV catalog entry for ``cve_id`` if present."""
        await self._refresh()
        return self._cve_ids.get(cve_id)

    async def aclose(self) -> None:
        await self._client.aclose()