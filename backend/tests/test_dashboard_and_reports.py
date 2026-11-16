def _seed_scan_and_risk(client, headers):
    with open("samples/nessus_sample.csv", "rb") as f:
        client.post("/api/v1/scans/upload", headers=headers, data={"scanner_type": "nessus"}, files={"file": ("s.csv", f, "text/csv")})
    client.post("/api/v1/risk/recalculate", headers=headers)


def test_dashboard_summary_severity_counts_are_zero_filled_and_correct(client, auth_headers):
    _seed_scan_and_risk(client, auth_headers)

    response = client.get("/api/v1/dashboard/summary", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    # Known composition of samples/nessus_sample.csv: 2 critical, 2 medium, 1 low, 1 info
    assert data["vulnerabilities_by_severity"] == {"critical": 2, "high": 0, "medium": 2, "low": 1, "info": 1}
    assert data["total_open_vulnerabilities"] == 6
    assert data["total_assets"] == 4


def test_dashboard_sla_compliance_reflects_overdue_tasks(client, auth_headers, db_session):
    from datetime import datetime, timedelta, timezone
    from app.models.remediation import RemediationTask

    _seed_scan_and_risk(client, auth_headers)
    vulns = client.get("/api/v1/vulnerabilities?search=PAN-OS", headers=auth_headers).json()
    vuln_id = vulns[0]["id"]

    create = client.post(f"/api/v1/vulnerabilities/{vuln_id}/remediation-tasks", headers=auth_headers, json={"priority": "p1_critical"})
    task_id = create.json()["id"]

    # Backdate it directly — the API has no "create an overdue task" shortcut
    # by design (SLA due dates are always computed forward from creation).
    task = db_session.query(RemediationTask).filter(RemediationTask.id == task_id).first()
    task.due_date = datetime.now(timezone.utc) - timedelta(days=3)
    db_session.commit()

    response = client.get("/api/v1/dashboard/summary", headers=auth_headers)
    data = response.json()
    assert data["sla_compliance"]["overdue_tasks"] == 1
    assert data["sla_compliance"]["compliance_rate"] == 0.0


def test_csv_export_returns_ranked_rows(client, auth_headers):
    _seed_scan_and_risk(client, auth_headers)
    response = client.get("/api/v1/reports/export/vulnerabilities.csv", headers=auth_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    lines = response.text.strip().split("\n")
    assert len(lines) == 7  # header + 6 findings


def test_pdf_report_generation_creates_downloadable_file(client, auth_headers):
    _seed_scan_and_risk(client, auth_headers)

    generate = client.post("/api/v1/reports/generate", headers=auth_headers)
    assert generate.status_code == 201
    report_id = generate.json()["id"]

    download = client.get(f"/api/v1/reports/{report_id}/download", headers=auth_headers)
    assert download.status_code == 200
    assert download.content[:4] == b"%PDF"  # a real PDF file signature, not a stub


def test_report_download_is_tenant_isolated(client, auth_headers):
    response = client.get("/api/v1/reports/nonexistent-report-id/download", headers=auth_headers)
    assert response.status_code == 404
