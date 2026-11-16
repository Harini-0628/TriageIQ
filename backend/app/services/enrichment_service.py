"""
Enrichment orchestration.

Design decision: the fetch functions are passed in as parameters with
real-network defaults (nvd_fetcher=fetch_cve_raw, etc.) rather than
imported and called directly. This is dependency injection applied
specifically so tests can substitute fixture-backed fake fetchers and
exercise the ENTIRE orchestration — batching, CVE selection, DB writes —
without any network access. In production nothing changes (the defaults
just work); in a sandboxed/CI environment the same function is fully
testable.
"""
import logging
from datetime import datetime, timezone
from typing import Callable, List, Optional

from sqlalchemy.orm import Session

from app.models.cve import CVE
from app.services.enrichment.nvd_client import fetch_cve_raw, parse_cve_response
from app.services.enrichment.epss_client import fetch_epss_batch_raw, parse_epss_response, chunk_cve_ids
from app.services.enrichment.kev_client import fetch_kev_catalog_raw, parse_kev_catalog

logger = logging.getLogger("triageiq.enrichment")


class EnrichmentSummary:
    def __init__(self):
        self.cves_processed = 0
        self.nvd_enriched = 0
        self.epss_enriched = 0
        self.kev_matches = 0
        self.nvd_not_found = 0


def get_cves_needing_enrichment(db: Session, limit: int = 500) -> List[CVE]:
    """
    A CVE 'needs enrichment' if we've never fetched data for it. Refreshing
    ALREADY-enriched CVEs on a schedule (EPSS changes daily even when CVSS
    doesn't) is Module 9's job (scheduler) — this function is specifically
    the "first enrichment" pass for newly-discovered CVE stubs.
    """
    return db.query(CVE).filter(CVE.enrichment_fetched_at.is_(None)).limit(limit).all()


def run_enrichment(
    db: Session,
    cves: List[CVE],
    nvd_fetcher: Callable[[str], Optional[dict]] = fetch_cve_raw,
    epss_fetcher: Callable[[List[str]], Optional[dict]] = fetch_epss_batch_raw,
    kev_fetcher: Callable[[], Optional[dict]] = fetch_kev_catalog_raw,
) -> EnrichmentSummary:
    summary = EnrichmentSummary()
    if not cves:
        return summary

    cve_ids = [c.cve_id for c in cves]
    now = datetime.now(timezone.utc)

    # --- KEV: one fetch for the whole catalog, regardless of how many CVEs we're enriching ---
    kev_catalog = {}
    kev_raw = kev_fetcher()
    if kev_raw:
        kev_catalog = parse_kev_catalog(kev_raw)

    # --- EPSS: batched ---
    epss_scores = {}
    for batch in chunk_cve_ids(cve_ids):
        epss_raw = epss_fetcher(batch)
        if epss_raw:
            epss_scores.update(parse_epss_response(epss_raw))

    # --- NVD: one call per CVE (no batch endpoint exists for exact-ID lookup) ---
    for cve in cves:
        summary.cves_processed += 1

        nvd_raw = nvd_fetcher(cve.cve_id)
        if nvd_raw:
            parsed = parse_cve_response(nvd_raw)
            if parsed.found:
                cve.description = parsed.description
                cve.cvss_v3_score = parsed.cvss_v3_score
                cve.cvss_v3_vector = parsed.cvss_v3_vector
                cve.cvss_v3_severity = parsed.cvss_v3_severity
                cve.published_date = parsed.published_date
                cve.last_modified_date = parsed.last_modified_date
                cve.raw_nvd_data = nvd_raw
                summary.nvd_enriched += 1
            else:
                summary.nvd_not_found += 1

        epss = epss_scores.get(cve.cve_id)
        if epss:
            cve.epss_score = epss.epss
            cve.epss_percentile = epss.percentile
            summary.epss_enriched += 1

        kev_entry = kev_catalog.get(cve.cve_id)
        if kev_entry:
            cve.is_known_exploited = True
            cve.kev_date_added = (
                datetime(kev_entry.date_added.year, kev_entry.date_added.month, kev_entry.date_added.day, tzinfo=timezone.utc)
                if kev_entry.date_added else None
            )
            cve.kev_ransomware_use = kev_entry.ransomware_use
            summary.kev_matches += 1

        cve.enrichment_fetched_at = now

    db.commit()
    logger.info(
        "Enrichment run completed",
        extra={"context": {
            "cves_processed": summary.cves_processed,
            "nvd_enriched": summary.nvd_enriched,
            "epss_enriched": summary.epss_enriched,
            "kev_matches": summary.kev_matches,
        }},
    )
    return summary
