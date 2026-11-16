"""
Verifies the enrichment module against REAL captured API response shapes
(fixtures/), and exercises the full orchestration (batching, DB writes,
"needs enrichment" selection) using injected fake fetchers — all without
any live network call, since this sandbox has no route to nvd.nist.gov,
api.first.org, or cisa.gov. The parse_* functions here are the same code
that runs against the real APIs in production; only the HTTP transport is
substituted.
"""
import json
from datetime import datetime, timezone

from app.db.session import SessionLocal
from app.models.cve import CVE
from app.services.enrichment.nvd_client import parse_cve_response
from app.services.enrichment.epss_client import parse_epss_response, chunk_cve_ids
from app.services.enrichment.kev_client import parse_kev_catalog
from app.services.enrichment_service import get_cves_needing_enrichment, run_enrichment

FIXTURES = "tests/fixtures"


def load(name):
    with open(f"{FIXTURES}/{name}") as f:
        return json.load(f)


# --- 1. Unit test: NVD parsing against a real captured response shape ---
nvd_result = parse_cve_response(load("nvd_cve_2024_3400.json"))
assert nvd_result.found is True
assert nvd_result.cvss_v3_score == 10.0
assert nvd_result.cvss_v3_severity == "CRITICAL"
assert "GlobalProtect" in nvd_result.description
assert nvd_result.published_date == datetime(2024, 4, 12, 0, 15, 47, 397000)
print("PASS: NVD parser correctly extracts CVSS score, severity, description, dates")

# --- 2. Unit test: NVD parsing when CVE not found ---
not_found = parse_cve_response(load("nvd_cve_not_found.json"))
assert not_found.found is False
print("PASS: NVD parser correctly handles a CVE ID with no results")

# --- 3. Unit test: EPSS parsing, including the string->float conversion gotcha ---
epss_scores = parse_epss_response(load("epss_batch.json"))
assert len(epss_scores) == 3
assert isinstance(epss_scores["CVE-2024-3400"].epss, float)
assert abs(epss_scores["CVE-2024-3400"].epss - 0.94382) < 0.0001
assert abs(epss_scores["CVE-2019-0708"].percentile - 0.99987) < 0.0001
print("PASS: EPSS parser correctly converts string scores to floats")

# --- 4. Unit test: CISA KEV parsing ---
kev_catalog = parse_kev_catalog(load("cisa_kev_catalog.json"))
assert "CVE-2024-3400" in kev_catalog
assert kev_catalog["CVE-2024-3400"].date_added.isoformat() == "2024-04-12"
assert kev_catalog["CVE-2024-3400"].ransomware_use is False
assert kev_catalog["CVE-2019-0708"].ransomware_use is True
assert "CVE-2018-15473" not in kev_catalog  # confirmed NOT in KEV
print("PASS: CISA KEV parser correctly identifies membership and ransomware flag")

# --- 5. Unit test: batching splits correctly ---
batches = chunk_cve_ids([f"CVE-2024-{i}" for i in range(250)], batch_size=100)
assert len(batches) == 3
assert len(batches[0]) == 100 and len(batches[2]) == 50
print("PASS: EPSS batching correctly chunks 250 CVEs into 3 batches (100/100/50)")


# --- 6. Integration test: full orchestration against the real (SQLite) database ---
db = SessionLocal()

# Set up CVE stubs like the ones Module 4's scan import would create —
# bare cve_id, no enrichment yet.
for cve_id in ["CVE-2024-3400", "CVE-2019-0708", "CVE-2018-15473"]:
    if not db.query(CVE).filter(CVE.cve_id == cve_id).first():
        db.add(CVE(cve_id=cve_id))
db.commit()

pending_before = get_cves_needing_enrichment(db)
pending_ids = {c.cve_id for c in pending_before}
assert {"CVE-2024-3400", "CVE-2019-0708", "CVE-2018-15473"}.issubset(pending_ids)
print(f"PASS: get_cves_needing_enrichment finds {len(pending_before)} unenriched CVE(s)")


def fake_nvd_fetcher(cve_id: str):
    # Only CVE-2024-3400 has a captured NVD fixture; the others simulate
    # "not yet fetched a real fixture for this one" by returning the
    # not-found shape — this proves the orchestration handles a MIX of
    # found/not-found results in one run, not just the happy path.
    if cve_id == "CVE-2024-3400":
        return load("nvd_cve_2024_3400.json")
    return load("nvd_cve_not_found.json")


def fake_epss_fetcher(cve_ids):
    return load("epss_batch.json")


def fake_kev_fetcher():
    return load("cisa_kev_catalog.json")


summary = run_enrichment(
    db, pending_before,
    nvd_fetcher=fake_nvd_fetcher,
    epss_fetcher=fake_epss_fetcher,
    kev_fetcher=fake_kev_fetcher,
)

assert summary.cves_processed == len(pending_before)
assert summary.nvd_enriched == 1       # only CVE-2024-3400 had a real NVD fixture
assert summary.nvd_not_found == len(pending_before) - 1
assert summary.epss_enriched == 3      # all 3 present in the EPSS fixture
assert summary.kev_matches == 2        # CVE-2024-3400 and CVE-2019-0708 are in the KEV fixture
print(f"PASS: run_enrichment summary correct — {summary.nvd_enriched} NVD, "
      f"{summary.epss_enriched} EPSS, {summary.kev_matches} KEV matches")

# Verify the actual DB rows were updated correctly
updated_cve = db.query(CVE).filter(CVE.cve_id == "CVE-2024-3400").first()
assert updated_cve.cvss_v3_score == 10.0
assert abs(updated_cve.epss_score - 0.94382) < 0.0001
assert updated_cve.is_known_exploited is True
assert updated_cve.kev_ransomware_use is False
assert updated_cve.enrichment_fetched_at is not None
print("PASS: CVE-2024-3400 row fully enriched in the database — CVSS, EPSS, and KEV all present")

bluekeep = db.query(CVE).filter(CVE.cve_id == "CVE-2019-0708").first()
assert bluekeep.cvss_v3_score is None  # no NVD fixture for this one in this run
assert bluekeep.is_known_exploited is True
assert bluekeep.kev_ransomware_use is True
print("PASS: CVE-2019-0708 correctly shows KEV+ransomware match despite no NVD data this run")

# Verify re-running enrichment now finds ZERO pending CVEs (all 3 marked enriched)
pending_after = get_cves_needing_enrichment(db)
pending_after_ids = {c.cve_id for c in pending_after}
assert not {"CVE-2024-3400", "CVE-2019-0708", "CVE-2018-15473"}.intersection(pending_after_ids)
print("PASS: re-running get_cves_needing_enrichment excludes all 3 now-enriched CVEs")

db.close()
print()
print("ALL ENRICHMENT CHECKS PASSED")
