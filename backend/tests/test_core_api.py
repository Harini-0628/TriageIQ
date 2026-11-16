def test_asset_update_changes_risk_score_on_recalculation(client, auth_headers):
    with open("samples/nessus_sample.csv", "rb") as f:
        client.post("/api/v1/scans/upload", headers=auth_headers, data={"scanner_type": "nessus"}, files={"file": ("s.csv", f, "text/csv")})

    assets = client.get("/api/v1/assets?search=prod-api-01", headers=auth_headers).json()
    asset_id = assets[0]["id"]

    client.post("/api/v1/risk/recalculate", headers=auth_headers)
    before = client.get("/api/v1/risk/queue", headers=auth_headers).json()
    before_score = next(v["composite_score"] for v in before if v["asset_hostname"] == "prod-api-01")

    client.patch(f"/api/v1/assets/{asset_id}", headers=auth_headers, json={"criticality": "critical", "internet_facing": True})
    client.post("/api/v1/risk/recalculate", headers=auth_headers)

    after = client.get("/api/v1/risk/queue", headers=auth_headers).json()
    after_score = next(v["composite_score"] for v in after if v["asset_hostname"] == "prod-api-01")

    assert after_score > before_score


def test_duplicate_asset_hostname_rejected(client, auth_headers):
    payload = {"hostname": "duplicate-host", "criticality": "medium"}
    first = client.post("/api/v1/assets", headers=auth_headers, json=payload)
    assert first.status_code == 201
    second = client.post("/api/v1/assets", headers=auth_headers, json=payload)
    assert second.status_code == 409


def test_vulnerability_status_change_is_audit_logged(client, auth_headers, db_session):
    from app.models.report_audit_notification import AuditLog

    with open("samples/nessus_sample.csv", "rb") as f:
        client.post("/api/v1/scans/upload", headers=auth_headers, data={"scanner_type": "nessus"}, files={"file": ("s.csv", f, "text/csv")})

    vulns = client.get("/api/v1/vulnerabilities?search=PAN-OS", headers=auth_headers).json()
    vuln_id = vulns[0]["id"]

    response = client.patch(f"/api/v1/vulnerabilities/{vuln_id}", headers=auth_headers,
                             json={"status": "in_progress", "reason": "assigned for patching"})
    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"

    log_entry = db_session.query(AuditLog).filter(AuditLog.action == "vulnerability.status_changed").first()
    assert log_entry is not None
    assert log_entry.details["from"] == "open"
    assert log_entry.details["to"] == "in_progress"
    assert log_entry.details["reason"] == "assigned for patching"


def test_remediation_task_default_sla_and_resolution(client, auth_headers):
    with open("samples/nessus_sample.csv", "rb") as f:
        client.post("/api/v1/scans/upload", headers=auth_headers, data={"scanner_type": "nessus"}, files={"file": ("s.csv", f, "text/csv")})

    vulns = client.get("/api/v1/vulnerabilities?search=PAN-OS", headers=auth_headers).json()
    vuln_id = vulns[0]["id"]

    create_response = client.post(f"/api/v1/vulnerabilities/{vuln_id}/remediation-tasks", headers=auth_headers,
                                   json={"priority": "p1_critical", "notes": "patch ASAP"})
    assert create_response.status_code == 201
    task = create_response.json()
    assert task["sla_days"] == 15  # default for P1_CRITICAL, none was specified
    assert task["is_overdue"] is False

    resolve_response = client.patch(f"/api/v1/remediation-tasks/{task['id']}", headers=auth_headers, json={"status": "resolved"})
    assert resolve_response.status_code == 200
    assert resolve_response.json()["resolved_at"] is not None
