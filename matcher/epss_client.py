"""FIRST EPSS API client.

Fetches Exploit Prediction Scoring System scores (probability of exploitation
in the next 30 days, 0.0–1.0) for CVE lists. Used to weight risk scoring.
"""

import logging
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger("network_mapper.epss")

EPSS_URL = "https://api.first.org/data/v1/epss"


class EPSSClient:
    """Async client for the FIRST EPSS API."""

    EPSS_URL = EPSS_URL

    def __init__(self, base_url: str = EPSS_URL, client: Optional[httpx.AsyncClient] = None) -> None:
        self.base_url = base_url
        self._client = client or httpx.AsyncClient(timeout=30.0)

    async def get_scores(self, cve_ids: List[str]) -> Dict[str, dict]:
        """Return ``{cve_id: {"score": float, "percentile": float}}``.

        Unknown or not-yet-scored CVEs are simply absent from the result.
        """
        if not cve_ids:
            return {}
        unique = list(dict.fromkeys(cve_ids))
        result: Dict[str, dict] = {}
        # The API accepts ~50 CVEs per request.
        for i in range(0, len(unique), 50):
            chunk = unique[i : i + 50]
            try:
                resp = await self._client.get(
                    self.base_url, params={"cve": ",".join(chunk)}
                )
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("data", []) or []:
                    cve = item.get("cve")
                    if not cve:
                        continue
                    score = item.get("epss")
                    percentile = item.get("percentile")
                    result[cve] = {
                        "score": float(score) if score is not None else 0.0,
                        "percentile": float(percentile) if percentile is not None else 0.0,
                    }
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("EPSS request failed: %s", exc)
        return result

    async def get_score(self, cve_id: str) -> dict:
        """Return the EPSS score dict for a single CVE (empty when unknown)."""
        scores = await self.get_scores([cve_id])
        return scores.get(cve_id, {})

    async def aclose(self) -> None:
        await self._client.aclose()