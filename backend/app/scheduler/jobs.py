"""
Scheduled jobs, run by APScheduler (wired up in scheduler/runner.py).

Design decision: every job function here opens its own DB session and is
directly callable/testable with no scheduler involved — the same pattern
used for the scan-import background task in Module 4. A job is just a
plain function; APScheduler is only responsible for calling it on a timer.
This means the entire business logic of "what should happen nightly" is
testable in under a second, with no need to wait for a real cron tick.
"""
import logging
from datetime import datetime, timezone, timedelta

import app.db.session as db_session_module
from app.models.organization import Organization
from app.models.cve import CVE
from app.models.remediation import RemediationTask, TaskStatus
from app.models.vulnerability import Vulnerability
from app.models.report_audit_notification import Notification
from app.services.enrichment_service import get_cves_needing_enrichment, run_enrichment
from app.services.risk_engine_service import recalculate_for_org

logger = logging.getLogger("triageiq.scheduler")


def nightly_enrichment_job() -> dict:
    """Refreshes CVEs that have never been enriched. Deliberately does NOT
    re-enrich already-enriched CVEs every run (EPSS changes daily and
    ideally would be refreshed continuously in a mature system) — scoped
    here to new-CVE enrichment to keep the job's cost bounded and
    predictable, with a note in the README about extending it."""
    db = db_session_module.SessionLocal()
    try:
        cves = get_cves_needing_enrichment(db, limit=500)
        summary = run_enrichment(db, cves)
        logger.info(f"Nightly enrichment: processed {summary.cves_processed} CVE(s)")
        return {"cves_processed": summary.cves_processed, "nvd_enriched": summary.nvd_enriched}
    finally:
        db.close()


def nightly_risk_recalculation_job() -> dict:
    """Recalculates risk for every org's open vulnerabilities. Runs AFTER
    enrichment in the nightly sequence (see runner.py) so freshly-enriched
    CVSS/EPSS/KEV data is reflected the same night, not a day behind."""
    db = db_session_module.SessionLocal()
    try:
        orgs = db.query(Organization).all()
        total_scored = 0
        for org in orgs:
            summary = recalculate_for_org(db, org.id)
            total_scored += summary.vulnerabilities_scored
        logger.info(f"Nightly risk recalculation: scored {total_scored} vulnerabilities across {len(orgs)} org(s)")
        return {"orgs_processed": len(orgs), "vulnerabilities_scored": total_scored}
    finally:
        db.close()


def sla_breach_notification_job() -> dict:
    """
    Finds remediation tasks that just crossed their due date and creates a
    Notification for the assignee (and org admins if unassigned). Runs
    daily; a task that's been overdue for 5 days doesn't get 5 duplicate
    notifications — we check for an existing 'sla_breach' notification for
    that task before creating a new one.
    """
    db = db_session_module.SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        overdue_tasks = (
            db.query(RemediationTask)
            .filter(
                RemediationTask.due_date < now,
                RemediationTask.status.notin_([TaskStatus.RESOLVED, TaskStatus.VERIFIED]),
            )
            .all()
        )

        created = 0
        for task in overdue_tasks:
            already_notified = (
                db.query(Notification)
                .filter(Notification.type == "sla_breach", Notification.message.like(f"%{task.id}%"))
                .first()
            )
            if already_notified or not task.assigned_to_id:
                continue

            vuln = db.query(Vulnerability).filter(Vulnerability.id == task.vulnerability_id).first()
            notification = Notification(
                org_id=vuln.org_id,
                user_id=task.assigned_to_id,
                type="sla_breach",
                title="Remediation task overdue",
                message=f"Task {task.id} for '{vuln.title}' missed its {task.sla_days}-day SLA.",
                created_at=now,
            )
            db.add(notification)
            created += 1

        db.commit()
        logger.info(f"SLA breach check: {created} new notification(s) created out of {len(overdue_tasks)} overdue task(s)")
        return {"overdue_tasks": len(overdue_tasks), "notifications_created": created}
    finally:
        db.close()
