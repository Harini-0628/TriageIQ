"""
Risk engine orchestration — pulls real Vulnerability/CVE/Asset rows,
delegates the actual math to the pure functions in risk_scoring.py, and
persists the result as a new RiskScore history row.
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session, joinedload

from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.models.cve import CVE
from app.models.asset import Asset
from app.models.risk_score import RiskScore
from app.repositories.risk_score_repository import RiskScoreRepository
from app.services.risk_scoring import calculate_risk_components, SCORE_VERSION

logger = logging.getLogger("triageiq.risk_engine")


class RecalculationSummary:
    def __init__(self):
        self.vulnerabilities_scored = 0
        self.highest_score = 0.0
        self.highest_score_title = None


def recalculate_for_vulnerability(db: Session, vuln: Vulnerability, now: Optional[datetime] = None) -> RiskScore:
    now = now or datetime.now(timezone.utc)

    cve: Optional[CVE] = db.query(CVE).filter(CVE.cve_id == vuln.cve_id).first() if vuln.cve_id else None
    asset: Asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()

    components = calculate_risk_components(
        cvss_v3_score=cve.cvss_v3_score if cve else None,
        epss_score=cve.epss_score if cve else None,
        is_known_exploited=cve.is_known_exploited if cve else False,
        kev_ransomware_use=cve.kev_ransomware_use if cve else None,
        asset_criticality=asset.criticality,
        internet_facing=asset.internet_facing,
        first_detected_at=vuln.first_detected_at,
        now=now,
    )

    risk_score = RiskScore(
        vulnerability_id=vuln.id,
        composite_score=components.composite,
        cvss_component=components.cvss,
        epss_component=components.epss,
        kev_component=components.kev,
        asset_criticality_component=components.asset_criticality,
        exposure_component=components.exposure,
        age_component=components.age,
        score_version=SCORE_VERSION,
        calculated_at=now,
    )
    RiskScoreRepository(db).create(risk_score)
    return risk_score


def recalculate_for_org(db: Session, org_id: str, statuses: Optional[List[VulnerabilityStatus]] = None) -> RecalculationSummary:
    """
    Recalculates every open (by default) vulnerability in an org. This is
    what a scheduled nightly job (Module 9) calls, and what fires
    immediately after a scan import or enrichment run so the ranked queue
    reflects the latest data without a stale window.
    """
    statuses = statuses or [VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]
    summary = RecalculationSummary()
    now = datetime.now(timezone.utc)

    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.org_id == org_id, Vulnerability.status.in_(statuses))
        .all()
    )

    for vuln in vulns:
        risk_score = recalculate_for_vulnerability(db, vuln, now=now)
        summary.vulnerabilities_scored += 1
        if risk_score.composite_score > summary.highest_score:
            summary.highest_score = risk_score.composite_score
            summary.highest_score_title = vuln.title

    db.commit()
    logger.info(
        "Risk recalculation completed",
        extra={"context": {"org_id": org_id, "scored": summary.vulnerabilities_scored, "highest": summary.highest_score}},
    )
    return summary


def get_ranked_queue(db: Session, org_id: str, limit: int = 50) -> List[dict]:
    """
    The core "risk explorer" query: every open vulnerability, joined to its
    LATEST risk score, ordered highest-risk-first. This is the single
    query a security team actually lives in every day — "what should I
    work on next" — and it's the thing to demo live in an interview.

    Implemented as a correlated subquery (latest RiskScore per
    vulnerability) rather than a naive join, because a naive join against
    the full RiskScore history table would return one row PER historical
    score, not one row per vulnerability — silently wrong, not just slow.
    """
    from sqlalchemy import func

    latest_score_subq = (
        db.query(
            RiskScore.vulnerability_id,
            func.max(RiskScore.calculated_at).label("latest_calculated_at"),
        )
        .group_by(RiskScore.vulnerability_id)
        .subquery()
    )

    rows = (
        db.query(Vulnerability, RiskScore, Asset)
        .join(latest_score_subq, latest_score_subq.c.vulnerability_id == Vulnerability.id)
        .join(
            RiskScore,
            (RiskScore.vulnerability_id == latest_score_subq.c.vulnerability_id)
            & (RiskScore.calculated_at == latest_score_subq.c.latest_calculated_at),
        )
        .join(Asset, Asset.id == Vulnerability.asset_id)
        .filter(Vulnerability.org_id == org_id)
        .filter(Vulnerability.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]))
        .order_by(RiskScore.composite_score.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "vulnerability_id": vuln.id,
            "title": vuln.title,
            "cve_id": vuln.cve_id,
            "asset_hostname": asset.hostname,
            "asset_criticality": asset.criticality.value,
            "status": vuln.status.value,
            "composite_score": score.composite_score,
            "cvss_component": score.cvss_component,
            "epss_component": score.epss_component,
            "kev_component": score.kev_component,
            "asset_criticality_component": score.asset_criticality_component,
            "exposure_component": score.exposure_component,
            "age_component": score.age_component,
            "calculated_at": score.calculated_at,
        }
        for vuln, score, asset in rows
    ]
