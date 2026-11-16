"""
Enrichment tests against REAL captured API response shapes (fixtures/) —
no live network, since this sandbox has no route to nvd.nist.gov,
api.first.org, or cisa.gov. See app/services/enrichment/*_client.py
docstrings for the fetch/parse split that makes this possible.
"""
import json

from app.services.enrichment.nvd_client import parse_cve_response
from app.services.enrichment.epss_client import parse_epss_response, chunk_cve_ids
from app.services.enrichment.kev_client import parse_kev_catalog
from app.services.enrichment_service import get_cves_needing_enrichment, run_enrichment


def _load_fixture(name):
    with open(f"tests/fixtures/{name}") as f:
        return json.load(f)


def test_nvd_parser_extracts_fields_from_real_response_shape():
    result = parse_cve_response(_load_fixture("nvd_cve_2024_3400.json"))
    assert result.found is True
    assert result.cvss_v3_score == 10.0
    assert result.cvss_v3_severity == "CRITICAL"
    assert "GlobalProtect" in result.description


def test_nvd_parser_handles_not_found():
    result = parse_cve_response(_load_fixture("nvd_cve_not_found.json"))
    assert result.found is False


def test_epss_parser_converts_string_scores_to_floats():
    scores = parse_epss_response(_load_fixture("epss_batch.json"))
    assert isinstance(scores["CVE-2024-3400"].epss, float)
    assert abs(scores["CVE-2024-3400"].epss - 0.94382) < 0.0001


def test_kev_parser_identifies_membership_and_ransomware_flag():
    catalog = parse_kev_catalog(_load_fixture("cisa_kev_catalog.json"))
    assert catalog["CVE-2024-3400"].ransomware_use is False
    assert catalog["CVE-2019-0708"].ransomware_use is True
    assert "CVE-2018-15473" not in catalog


def test_chunking_splits_correctly():
    batches = chunk_cve_ids([f"CVE-2024-{i}" for i in range(250)], batch_size=100)
    assert [len(b) for b in batches] == [100, 100, 50]


def test_full_enrichment_orchestration_against_real_db(db_session):
    from app.models.cve import CVE

    for cve_id in ["CVE-2024-3400", "CVE-2019-0708", "CVE-2018-15473"]:
        db_session.add(CVE(cve_id=cve_id))
    db_session.commit()

    pending = get_cves_needing_enrichment(db_session)
    assert len(pending) == 3

    def fake_nvd(cve_id):
        return _load_fixture("nvd_cve_2024_3400.json") if cve_id == "CVE-2024-3400" else _load_fixture("nvd_cve_not_found.json")

    summary = run_enrichment(
        db_session, pending,
        nvd_fetcher=fake_nvd,
        epss_fetcher=lambda ids: _load_fixture("epss_batch.json"),
        kev_fetcher=lambda: _load_fixture("cisa_kev_catalog.json"),
    )

    assert summary.nvd_enriched == 1
    assert summary.epss_enriched == 3
    assert summary.kev_matches == 2

    updated = db_session.query(CVE).filter(CVE.cve_id == "CVE-2024-3400").first()
    assert updated.cvss_v3_score == 10.0
    assert updated.is_known_exploited is True

    # Re-running the "needs enrichment" query must now find nothing
    assert get_cves_needing_enrichment(db_session) == []
