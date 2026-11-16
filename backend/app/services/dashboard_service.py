"""
Dashboard aggregation — the executive-facing numbers that summarize
everything Modules 4-7 built. Deliberately a single service function
returning one shaped payload, rather than several small endpoints the
frontend has to stitch together, because a dashboard that requires 6
sequential API calls to render is a dashboard nobody trusts to load fast.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, VulnerabilityStatus, ScannerSeverity
from app.models.cve import CVE
from app.models.risk_score import RiskScore
from app.models.remediation import RemediationTask, TaskStatus


def get_dashboard_summary(db: Session, org_id: str) -> dict:
    open_statuses = [VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]

    total_assets = db.query(Asset).filter(Asset.org_id == org_id).count()

    total_open = (
        db.query(Vulnerability)
        .filter(Vulnerability.org_id == org_id, Vulnerability.status.in_(open_statuses))
        .count()
    )

    by_severity_rows = (
        db.query(Vulnerability.scanner_severity, func.count(Vulnerability.id))
        .filter(Vulnerability.org_id == org_id, Vulnerability.status.in_(open_statuses))
        .group_by(Vulnerability.scanner_severity)
        .all()
    )
    # Zero-fill every severity level explicitly — a dashboard that just
    # omits "critical: 0" instead of showing it is easy to misread as
    # "we don't track that," which is the opposite of what a security
    # dashboard should ever imply.
    by_severity = {s.value: 0 for s in ScannerSeverity}
    for severity, count in by_severity_rows:
        by_severity[severity.value] = count

    by_status_rows = (
        db.query(Vulnerability.status, func.count(Vulnerability.id))
        .filter(Vulnerability.org_id == org_id)
        .group_by(Vulnerability.status)
        .all()
    )
    by_status = {s.value: 0 for s in VulnerabilityStatus}
    for vstatus, count in by_status_rows:
        by_status[vstatus.value] = count

    # Average of each open vulnerability's LATEST risk score
    latest_score_subq = (
        db.query(RiskScore.vulnerability_id, func.max(RiskScore.calculated_at).label("latest_calculated_at"))
        .group_by(RiskScore.vulnerability_id)
        .subquery()
    )
    avg_score_row = (
        db.query(func.avg(RiskScore.composite_score))
        .join(latest_score_subq, (RiskScore.vulnerability_id == latest_score_subq.c.vulnerability_id)
              & (RiskScore.calculated_at == latest_score_subq.c.latest_calculated_at))
        .join(Vulnerability, Vulnerability.id == RiskScore.vulnerability_id)
        .filter(Vulnerability.org_id == org_id, Vulnerability.status.in_(open_statuses))
        .scalar()
    )
    average_risk_score = round(avg_score_row, 2) if avg_score_row is not None else None

    known_exploited_open_count = (
        db.query(Vulnerability)
        .join(CVE, CVE.cve_id == Vulnerability.cve_id)
        .filter(Vulnerability.org_id == org_id, Vulnerability.status.in_(open_statuses), CVE.is_known_exploited.is_(True))
        .count()
    )

    # Top 5 riskiest assets by their single highest-scored open vulnerability
    top_assets_rows = (
        db.query(
            Asset.hostname, Asset.criticality,
            func.count(Vulnerability.id).label("open_count"),
            func.max(RiskScore.composite_score).label("max_score"),
        )
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .join(latest_score_subq, latest_score_subq.c.vulnerability_id == Vulnerability.id)
        .join(RiskScore, (RiskScore.vulnerability_id == latest_score_subq.c.vulnerability_id)
              & (RiskScore.calculated_at == latest_score_subq.c.latest_calculated_at))
        .filter(Asset.org_id == org_id, Vulnerability.status.in_(open_statuses))
        .group_by(Asset.id, Asset.hostname, Asset.criticality)
        .order_by(func.max(RiskScore.composite_score).desc())
        .limit(5)
        .all()
    )
    top_risky_assets = [
        {"hostname": hostname, "criticality": criticality.value, "open_vulnerability_count": open_count, "highest_risk_score": max_score}
        for hostname, criticality, open_count, max_score in top_assets_rows
    ]

    # SLA compliance
    now = datetime.now(timezone.utc)
    active_tasks = (
        db.query(RemediationTask)
        .join(Vulnerability, Vulnerability.id == RemediationTask.vulnerability_id)
        .filter(Vulnerability.org_id == org_id, RemediationTask.status.notin_([TaskStatus.RESOLVED, TaskStatus.VERIFIED]))
        .all()
    )
    total_tasks = len(active_tasks)
    overdue_tasks = sum(
        1 for t in active_tasks
        if (t.due_date if t.due_date.tzinfo else t.due_date.replace(tzinfo=timezone.utc)) < now
    )
    compliance_rate = round(((total_tasks - overdue_tasks) / total_tasks) * 100, 1) if total_tasks > 0 else 100.0

    return {
        "total_assets": total_assets,
        "total_open_vulnerabilities": total_open,
        "vulnerabilities_by_severity": by_severity,
        "vulnerabilities_by_status": by_status,
        "average_risk_score": average_risk_score,
        "known_exploited_open_count": known_exploited_open_count,
        "top_risky_assets": top_risky_assets,
        "sla_compliance": {
            "total_tasks": total_tasks,
            "overdue_tasks": overdue_tasks,
            "compliance_rate": compliance_rate,
        },
    }
