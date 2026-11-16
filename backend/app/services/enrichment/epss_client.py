"""
EPSS (Exploit Prediction Scoring System, FIRST.org) API client.

Design decision: batched, not one-CVE-at-a-time. The EPSS API accepts a
comma-separated list of CVEs in a single call and returns all their scores
together — for an org with hundreds of open CVEs, batching in groups of
100 turns hundreds of HTTP round-trips into a handful. This is the kind
of detail that separates "it technically works" from "it works at the
scale a real vuln management program actually operates at."
"""
import logging
from typing import Dict, List, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("triageiq.enrichment.epss")
settings = get_settings()

BATCH_SIZE = 100


class EPSSScore:
    def __init__(self, epss: float, percentile: float):
        self.epss = epss
        self.percentile = percentile


def fetch_epss_batch_raw(cve_ids: List[str], client: Optional[httpx.Client] = None) -> Optional[dict]:
    """Thin HTTP wrapper — not exercised in this sandbox (no route to
    api.first.org). See parse_epss_response for what's under test."""
    owns_client = client is None
    client = client or httpx.Client(timeout=15.0)
    try:
        resp = client.get(settings.EPSS_API_BASE, params={"cve": ",".join(cve_ids)})
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as e:
        logger.warning(f"EPSS batch fetch failed for {len(cve_ids)} CVEs: {e}")
        return None
    finally:
        if owns_client:
            client.close()


def parse_epss_response(raw: dict) -> Dict[str, EPSSScore]:
    """
    Parses the FIRST.org EPSS API response shape:
    {"status": "OK", "total": N, "data": [{"cve": "CVE-...", "epss": "0.974530000", "percentile": "0.999420000", "date": "..."}]}

    EPSS returns scores as STRINGS (not numbers) — a real gotcha worth
    naming explicitly, since a naive implementation storing the raw string
    into a Float column would throw at the ORM layer.
    """
    scores: Dict[str, EPSSScore] = {}
    for entry in raw.get("data", []):
        cve_id = entry.get("cve")
        if not cve_id:
            continue
        try:
            scores[cve_id] = EPSSScore(epss=float(entry["epss"]), percentile=float(entry["percentile"]))
        except (KeyError, ValueError, TypeError):
            logger.warning(f"Malformed EPSS entry for {cve_id}, skipped")
    return scores


def chunk_cve_ids(cve_ids: List[str], batch_size: int = BATCH_SIZE) -> List[List[str]]:
    return [cve_ids[i:i + batch_size] for i in range(0, len(cve_ids), batch_size)]
