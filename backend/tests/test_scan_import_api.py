"""Scan import tests — parsing correctness is tested separately in
test_csv_parsers.py (pure, no DB); these test the full DB-backed pipeline."""


def _upload_and_wait(client, headers, scanner_type, filename):
    with open(f"samples/{filename}", "rb") as f:
        response = client.post(
            "/api/v1/scans/upload",
            headers=headers,
            data={"scanner_type": scanner_type},
            files={"file": (filename, f, "text/csv")},
        )
    assert response.status_code == 202
    scan_id = response.json()["id"]

    # BackgroundTasks run synchronously with TestClient (no real network
    # round-trip), so a single poll is enough — no sleep/retry loop needed
    # the way it was against a real running server.
    status_response = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    return status_response.json()


def test_nessus_upload_creates_correct_findings_and_assets(client, auth_headers):
    result = _upload_and_wait(client, auth_headers, "nessus", "nessus_sample.csv")
    assert result["status"] == "completed"
    assert result["total_rows"] == 6
    assert result["findings_created"] == 6
    assert result["assets_created"] == 4  # 3 rows share prod-api-01


def test_reupload_same_file_is_fully_deduplicated(client, auth_headers):
    _upload_and_wait(client, auth_headers, "nessus", "nessus_sample.csv")
    second = _upload_and_wait(client, auth_headers, "nessus", "nessus_sample.csv")
    assert second["findings_created"] == 0
    assert second["assets_created"] == 0


def test_openvas_multi_cve_finding_splits_correctly(client, auth_headers):
    result = _upload_and_wait(client, auth_headers, "openvas", "openvas_sample.csv")
    assert result["status"] == "completed"
    assert result["total_rows"] == 4
    assert result["findings_created"] == 5  # Log4Shell row has 2 CVEs -> 2 rows
    assert result["assets_created"] == 2


def test_non_csv_upload_rejected(client, auth_headers):
    response = client.post(
        "/api/v1/scans/upload",
        headers=auth_headers,
        data={"scanner_type": "nessus"},
        files={"file": ("not_a_scan.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 400


def test_remediated_finding_reopens_on_rescan(client, auth_headers, db_session):
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    _upload_and_wait(client, auth_headers, "nessus", "nessus_sample.csv")

    vuln = db_session.query(Vulnerability).filter(Vulnerability.title == "PAN-OS GlobalProtect Command Injection").first()
    vuln.status = VulnerabilityStatus.REMEDIATED
    db_session.commit()

    _upload_and_wait(client, auth_headers, "nessus", "nessus_sample.csv")

    db_session.refresh(vuln)
    assert vuln.status == VulnerabilityStatus.OPEN
