"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

Design decision: unlike NVD/EPSS, there's no per-CVE query endpoint — CISA
publishes the ENTIRE catalog (~1,200+ entries, ~500KB) as one JSON file on
every request. So we fetch it once per enrichment run and build an in-memory
lookup dict, rather than making any kind of per-CVE call. This is the
single highest-signal input into the risk score (Module 6) despite being
the simplest to integrate — CISA has already done the hard work of
confirming real-world exploitation.
"""
import logging
from datetime import datetime, date
from typing import Dict, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("triageiq.enrichment.kev")
settings = get_settings()


class KEVEntry:
    def __init__(self, date_added: Optional[date], ransomware_use: bool):
        self.date_added = date_added
        self.ransomware_use = ransomware_use


def fetch_kev_catalog_raw(client: Optional[httpx.Client] = None) -> Optional[dict]:
    """Thin HTTP wrapper — not exercised in this sandbox (no route to
    cisa.gov). See parse_kev_catalog for what's under test."""
    owns_client = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        resp = client.get(settings.CISA_KEV_URL)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as e:
        logger.warning(f"CISA KEV catalog fetch failed: {e}")
        return None
    finally:
        if owns_client:
            client.close()


def parse_kev_catalog(raw: dict) -> Dict[str, KEVEntry]:
    """
    Parses the CISA KEV JSON feed shape:
    {"catalogVersion": "...", "dateReleased": "...", "count": N,
     "vulnerabilities": [{"cveID", "dateAdded" (YYYY-MM-DD),
     "knownRansomwareCampaignUse": "Known"|"Unknown", ...}]}
    """
    catalog: Dict[str, KEVEntry] = {}
    for entry in raw.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        date_added = _parse_kev_date(entry.get("dateAdded"))
        ransomware_use = entry.get("knownRansomwareCampaignUse") == "Known"
        catalog[cve_id] = KEVEntry(date_added=date_added, ransomware_use=ransomware_use)
    return catalog


def _parse_kev_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None
