"""
NVD (National Vulnerability Database) API 2.0 client.

Design decision: fetch (the HTTP call) and parse (turning the raw response
into our own shape) are two separate functions, not one. This is what
makes the parsing logic unit-testable with a captured fixture response,
with zero network dependency — genuinely important here since the sandbox
this was built in has no route to nvd.nist.gov, so `parse_cve_response` is
what's actually exercised in CI, while `fetch_cve` is the thin, deliberately
boring wrapper around it that talks to the real network in a real deployment.
"""
import logging
import time
from datetime import datetime
from typing import Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("triageiq.enrichment.nvd")
settings = get_settings()

# Without an API key, NVD allows 5 requests per rolling 30s window.
# With a key: 50 per 30s. We rate-limit conservatively either way.
_MIN_SECONDS_BETWEEN_REQUESTS = 6.0 if not settings.NVD_API_KEY else 0.6


class NVDParsedResult:
    def __init__(self):
        self.cvss_v3_score: Optional[float] = None
        self.cvss_v3_vector: Optional[str] = None
        self.cvss_v3_severity: Optional[str] = None
        self.description: Optional[str] = None
        self.published_date: Optional[datetime] = None
        self.last_modified_date: Optional[datetime] = None
        self.found = False


def fetch_cve_raw(cve_id: str, client: Optional[httpx.Client] = None) -> Optional[dict]:
    """Thin wrapper around the real NVD HTTP call. Not exercised in this
    sandbox (no network route to nvd.nist.gov) — see parse_cve_response for
    what's actually under test."""
    owns_client = client is None
    client = client or httpx.Client(timeout=15.0)
    try:
        headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
        resp = client.get(settings.NVD_API_BASE, params={"cveId": cve_id}, headers=headers)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as e:
        logger.warning(f"NVD fetch failed for {cve_id}: {e}")
        return None
    finally:
        if owns_client:
            client.close()
        time.sleep(_MIN_SECONDS_BETWEEN_REQUESTS)


def parse_cve_response(raw: dict) -> NVDParsedResult:
    """
    Parses the NVD API 2.0 response shape:
    {"vulnerabilities": [{"cve": {"id", "published", "lastModified",
     "descriptions": [{"lang", "value"}],
     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore", "baseSeverity", "vectorString"}}]}
    }}]}

    We prefer cvssMetricV31, falling back to V30, because CVEs published
    before CVSS v3.1 existed (pre-2019ish) only carry the older metric.
    """
    result = NVDParsedResult()

    vulnerabilities = raw.get("vulnerabilities") or []
    if not vulnerabilities:
        return result  # found=False — a CVE ID that NVD doesn't recognize

    cve = vulnerabilities[0].get("cve", {})
    result.found = True

    descriptions = cve.get("descriptions", [])
    english_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
    result.description = english_desc

    if cve.get("published"):
        result.published_date = _parse_nvd_datetime(cve["published"])
    if cve.get("lastModified"):
        result.last_modified_date = _parse_nvd_datetime(cve["lastModified"])

    metrics = cve.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
    if cvss_list:
        cvss_data = cvss_list[0].get("cvssData", {})
        result.cvss_v3_score = cvss_data.get("baseScore")
        result.cvss_v3_vector = cvss_data.get("vectorString")
        result.cvss_v3_severity = cvss_data.get("baseSeverity")

    return result


def _parse_nvd_datetime(value: str) -> Optional[datetime]:
    # NVD timestamps look like "2024-04-12T00:15:47.397" — no timezone
    # suffix, but NVD documents everything as UTC.
    try:
        return datetime.fromisoformat(value).replace(tzinfo=None)
    except ValueError:
        return None
