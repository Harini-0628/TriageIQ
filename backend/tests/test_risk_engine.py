from datetime import datetime, timezone, timedelta

from app.models.organization import Organization
from app.models.asset import Asset, AssetType, AssetCriticality, Environment
from app.models.cve import CVE
from app.models.vulnerability import Vulnerability, ScannerSeverity, VulnerabilityStatus
from app.services.risk_engine_service import recalculate_for_org, recalculate_for_vulnerability, get_ranked_queue
from app.repositories.risk_score_repository import RiskScoreRepository


def _seed(db):
    now = datetime.now(timezone.utc)
    org = Organization(name="RiskTest Corp", slug="risktest-corp")
    db.add(org)
    db.flush()

    asset_critical = Asset(org_id=org.id, hostname="prod-payments-01", asset_type=AssetType.SERVER,
                            criticality=AssetCriticality.CRITICAL, environment=Environment.PRODUCTION, internet_facing=True)
    asset_low = Asset(org_id=org.id, hostname="dev-sandbox-07", asset_type=AssetType.SERVER,
                       criticality=AssetCriticality.LOW, environment=Environment.DEVELOPMENT, internet_facing=False)
    db.add_all([asset_critical, asset_low])
    db.flush()

    cve = CVE(cve_id="CVE-2024-9999", cvss_v3_score=9.1, epss_score=0.87, is_known_exploited=True, kev_ransomware_use=False)
    db.add(cve)
    db.flush()

    v1 = Vulnerability(org_id=org.id, asset_id=asset_critical.id, cve_id=cve.cve_id,
                        title="Critical RCE on payments service", scanner_severity=ScannerSeverity.CRITICAL,
                        status=VulnerabilityStatus.OPEN, port=443, first_detected_at=now - timedelta(days=5), last_detected_at=now)
    v2 = Vulnerability(org_id=org.id, asset_id=asset_low.id, cve_id=cve.cve_id,
                        title="Same RCE, but on a dev sandbox", scanner_severity=ScannerSeverity.CRITICAL,
                        status=VulnerabilityStatus.OPEN, port=443, first_detected_at=now - timedelta(days=5), last_detected_at=now)
    db.add_all([v1, v2])
    db.commit()
    return org, v1, v2


def test_same_cve_scores_higher_on_more_critical_asset(db_session):
    org, v1, v2 = _seed(db_session)
    recalculate_for_org(db_session, org.id)

    score1 = RiskScoreRepository(db_session).get_latest_for_vulnerability(v1.id)
    score2 = RiskScoreRepository(db_session).get_latest_for_vulnerability(v2.id)
    assert score1.composite_score > score2.composite_score


def test_ranked_queue_orders_highest_risk_first(db_session):
    org, v1, v2 = _seed(db_session)
    recalculate_for_org(db_session, org.id)

    queue = get_ranked_queue(db_session, org.id, limit=10)
    assert len(queue) == 2
    assert queue[0]["vulnerability_id"] == v1.id
    assert queue[0]["composite_score"] >= queue[1]["composite_score"]


def test_score_history_shows_the_trend_when_kev_status_changes(db_session):
    org, v1, _ = _seed(db_session)
    now = datetime.now(timezone.utc)

    cve_evolving = CVE(cve_id="CVE-2024-8888", cvss_v3_score=7.2, epss_score=0.15, is_known_exploited=False)
    db_session.add(cve_evolving)
    db_session.flush()
    vuln = Vulnerability(org_id=org.id, asset_id=v1.asset_id, cve_id=cve_evolving.cve_id,
                          title="Finding that will later get weaponized", scanner_severity=ScannerSeverity.HIGH,
                          status=VulnerabilityStatus.OPEN, port=8443, first_detected_at=now - timedelta(days=20), last_detected_at=now)
    db_session.add(vuln)
    db_session.commit()

    before = recalculate_for_vulnerability(db_session, vuln, now=now - timedelta(days=7))
    db_session.commit()

    cve_evolving.is_known_exploited = True
    cve_evolving.kev_ransomware_use = True
    cve_evolving.epss_score = 0.91
    db_session.commit()

    after = recalculate_for_vulnerability(db_session, vuln, now=now)
    db_session.commit()

    assert after.composite_score > before.composite_score
    history = RiskScoreRepository(db_session).get_history_for_vulnerability(vuln.id)
    assert len(history) == 2, "Recalculation must APPEND a new row, not overwrite the old one"
