"""
Scheduler job tests. Like scan_import_service, these jobs open their own
session via a live app.db.session.SessionLocal lookup — the db_session
fixture's monkeypatch (see conftest.py) makes that resolve to the same
isolated in-memory test database used everywhere else in the test.
"""
from datetime import datetime, timedelta, timezone

from app.scheduler.jobs import nightly_enrichment_job, nightly_risk_recalculation_job, sla_breach_notification_job


def test_nightly_enrichment_job_processes_pending_cves(db_session):
    from app.models.cve import CVE

    db_session.add(CVE(cve_id="CVE-2024-1111"))
    db_session.add(CVE(cve_id="CVE-2024-2222"))
    db_session.commit()

    result = nightly_enrichment_job()
    assert result["cves_processed"] == 2

    updated = db_session.query(CVE).filter(CVE.cve_id == "CVE-2024-1111").first()
    assert updated.enrichment_fetched_at is not None


def test_nightly_risk_recalculation_job_scores_across_orgs(client, auth_headers, db_session):
    with open("samples/nessus_sample.csv", "rb") as f:
        client.post("/api/v1/scans/upload", headers=auth_headers, data={"scanner_type": "nessus"}, files={"file": ("s.csv", f, "text/csv")})

    result = nightly_risk_recalculation_job()
    assert result["orgs_processed"] == 1
    assert result["vulnerabilities_scored"] == 6


def test_sla_breach_job_dedups_on_repeat_runs(client, auth_headers, db_session):
    from app.models.remediation import RemediationTask
    from app.models.user import User

    with open("samples/nessus_sample.csv", "rb") as f:
        client.post("/api/v1/scans/upload", headers=auth_headers, data={"scanner_type": "nessus"}, files={"file": ("s.csv", f, "text/csv")})

    vulns = client.get("/api/v1/vulnerabilities?search=PAN-OS", headers=auth_headers).json()
    user_id = db_session.query(User).first().id

    create = client.post(f"/api/v1/vulnerabilities/{vulns[0]['id']}/remediation-tasks", headers=auth_headers,
                          json={"priority": "p1_critical", "assigned_to_id": user_id})
    task_id = create.json()["id"]

    task = db_session.query(RemediationTask).filter(RemediationTask.id == task_id).first()
    task.due_date = datetime.now(timezone.utc) - timedelta(days=3)
    db_session.commit()

    first_run = sla_breach_notification_job()
    assert first_run == {"overdue_tasks": 1, "notifications_created": 1}

    second_run = sla_breach_notification_job()
    assert second_run == {"overdue_tasks": 1, "notifications_created": 0}
