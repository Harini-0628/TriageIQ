"""
Integration test for the risk engine against the real (SQLite) database —
proves recalculate_for_org and get_ranked_queue work against actual rows,
not just the pure formula in isolation. Also proves the "score jumps when
KEV status changes" trend story the README promises.
"""
from datetime import datetime, timezone, timedelta

from app.db.session import SessionLocal
from app.models.organization import Organization
from app.models.asset import Asset, AssetType, AssetCriticality, Environment
from app.models.cve import CVE
from app.models.vulnerability import Vulnerability, ScannerSeverity, VulnerabilityStatus
from app.services.risk_engine_service import recalculate_for_org, recalculate_for_vulnerability, get_ranked_queue
from app.repositories.risk_score_repository import RiskScoreRepository

db = SessionLocal()
now = datetime.now(timezone.utc)

org = Organization(name="RiskTest Corp", slug="risktest-corp")
db.add(org)
db.flush()

# Asset A: critical, internet-facing — everything is a bigger deal here
asset_critical = Asset(org_id=org.id, hostname="prod-payments-01", asset_type=AssetType.SERVER,
                        criticality=AssetCriticality.CRITICAL, environment=Environment.PRODUCTION, internet_facing=True)
# Asset B: low criticality, internal — same CVE should score lower here
asset_low = Asset(org_id=org.id, hostname="dev-sandbox-07", asset_type=AssetType.SERVER,
                   criticality=AssetCriticality.LOW, environment=Environment.DEVELOPMENT, internet_facing=False)
db.add_all([asset_critical, asset_low])
db.flush()

cve_bad = CVE(cve_id="CVE-2024-9999", cvss_v3_score=9.1, epss_score=0.87, is_known_exploited=True, kev_ransomware_use=False)
db.add(cve_bad)
db.flush()

vuln_on_critical = Vulnerability(
    org_id=org.id, asset_id=asset_critical.id, cve_id=cve_bad.cve_id,
    title="Critical RCE on payments service", scanner_severity=ScannerSeverity.CRITICAL,
    status=VulnerabilityStatus.OPEN, port=443,
    first_detected_at=now - timedelta(days=5), last_detected_at=now,
)
vuln_on_low = Vulnerability(
    org_id=org.id, asset_id=asset_low.id, cve_id=cve_bad.cve_id,
    title="Same RCE, but on a dev sandbox", scanner_severity=ScannerSeverity.CRITICAL,
    status=VulnerabilityStatus.OPEN, port=443,
    first_detected_at=now - timedelta(days=5), last_detected_at=now,
)
db.add_all([vuln_on_critical, vuln_on_low])
db.commit()

# --- Test 1: recalculate_for_org scores both vulnerabilities ---
summary = recalculate_for_org(db, org.id)
assert summary.vulnerabilities_scored == 2
print(f"PASS: recalculate_for_org scored {summary.vulnerabilities_scored} vulnerabilities, highest={summary.highest_score}")

# --- Test 2: same CVE scores HIGHER on the critical asset than the low one ---
score_critical = RiskScoreRepository(db).get_latest_for_vulnerability(vuln_on_critical.id)
score_low = RiskScoreRepository(db).get_latest_for_vulnerability(vuln_on_low.id)
assert score_critical.composite_score > score_low.composite_score
print(f"PASS: identical CVE scores {score_critical.composite_score} on critical/internet-facing asset "
      f"vs {score_low.composite_score} on low-criticality/internal asset — asset context correctly changes risk")

# --- Test 3: ranked queue returns highest-risk first ---
queue = get_ranked_queue(db, org.id, limit=10)
assert len(queue) == 2
assert queue[0]["vulnerability_id"] == vuln_on_critical.id, "Highest-risk finding must be first in the queue"
assert queue[0]["composite_score"] >= queue[1]["composite_score"]
print(f"PASS: ranked queue correctly orders highest-risk first: "
      f"[{queue[0]['title']} ({queue[0]['composite_score']})] before [{queue[1]['title']} ({queue[1]['composite_score']})]")

# --- Test 4: THE trend scenario — score jumps when KEV status changes ---
# Simulate: this CVE was NOT known-exploited when first scored, then CISA
# adds it to KEV a week later. The score history should show the jump.
cve_evolving = CVE(cve_id="CVE-2024-8888", cvss_v3_score=7.2, epss_score=0.15, is_known_exploited=False)
db.add(cve_evolving)
db.flush()
vuln_evolving = Vulnerability(
    org_id=org.id, asset_id=asset_critical.id, cve_id=cve_evolving.cve_id,
    title="Finding that will later get weaponized", scanner_severity=ScannerSeverity.HIGH,
    status=VulnerabilityStatus.OPEN, port=8443,
    first_detected_at=now - timedelta(days=20), last_detected_at=now,
)
db.add(vuln_evolving)
db.commit()

score_before = recalculate_for_vulnerability(db, vuln_evolving, now=now - timedelta(days=7))
db.commit()

# A week later, CISA confirms active exploitation and it enters KEV
cve_evolving.is_known_exploited = True
cve_evolving.kev_ransomware_use = True
cve_evolving.epss_score = 0.91  # EPSS also jumps once exploitation is confirmed, as it does in reality
db.commit()

score_after = recalculate_for_vulnerability(db, vuln_evolving, now=now)
db.commit()

assert score_after.composite_score > score_before.composite_score
history = RiskScoreRepository(db).get_history_for_vulnerability(vuln_evolving.id)
assert len(history) == 2, "Recalculation must APPEND a new row, not overwrite the old one"
print(f"PASS: score history shows the real trend — {score_before.composite_score} -> {score_after.composite_score} "
      f"after KEV+ransomware confirmed and EPSS jumped ({len(history)} history rows preserved)")

db.close()
print()
print("ALL RISK ENGINE INTEGRATION CHECKS PASSED")
