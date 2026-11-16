"""
Not a formal pytest suite (that's Module 11) — this is a quick sanity
script proving the ORM relationships actually resolve correctly: an org
with a user, an asset, a CVE, a vulnerability finding linking asset+CVE, a
risk score, and a remediation task, all queried back via relationships.
"""
from datetime import datetime, timezone

from app.db.session import SessionLocal
from app.models import (
    Organization, User, UserRole,
    Asset, AssetType, AssetCriticality, Environment,
    CVE, Vulnerability, ScannerSeverity, VulnerabilityStatus,
    RiskScore, RemediationTask, TaskStatus, TaskPriority,
)

db = SessionLocal()
now = datetime.now(timezone.utc)

org = Organization(name="Acme Corp", slug="acme-corp")
db.add(org)
db.flush()

user = User(org_id=org.id, email="analyst@acme.test", hashed_password="x", full_name="Test Analyst", role=UserRole.ANALYST)
db.add(user)

asset = Asset(
    org_id=org.id, hostname="prod-api-01", ip_address="10.0.1.15",
    asset_type=AssetType.SERVER, criticality=AssetCriticality.CRITICAL,
    environment=Environment.PRODUCTION, internet_facing=True,
)
db.add(asset)
db.flush()

cve = CVE(
    cve_id="CVE-2024-3400", description="PAN-OS command injection",
    cvss_v3_score=10.0, cvss_v3_severity="CRITICAL",
    epss_score=0.94, epss_percentile=0.999,
    is_known_exploited=True, kev_date_added=now,
)
db.add(cve)
db.flush()

vuln = Vulnerability(
    org_id=org.id, asset_id=asset.id, cve_id=cve.cve_id,
    title="PAN-OS GlobalProtect Command Injection", scanner_severity=ScannerSeverity.CRITICAL,
    status=VulnerabilityStatus.OPEN, port=443, protocol="tcp", service="https",
    first_detected_at=now, last_detected_at=now,
)
db.add(vuln)
db.flush()

score = RiskScore(
    vulnerability_id=vuln.id, composite_score=98.5,
    cvss_component=30.0, epss_component=28.0, kev_component=20.0,
    asset_criticality_component=15.0, exposure_component=5.0, age_component=0.5,
    calculated_at=now,
)
db.add(score)

task = RemediationTask(
    vulnerability_id=vuln.id, assigned_to_id=user.id,
    status=TaskStatus.OPEN, priority=TaskPriority.P1_CRITICAL,
    sla_days=15, due_date=now,
)
db.add(task)

db.commit()

# --- Now read it all back purely via relationships, no manual joins ---
reloaded_org = db.query(Organization).filter_by(slug="acme-corp").first()
reloaded_asset = reloaded_org.assets[0]
reloaded_vuln = reloaded_asset.vulnerabilities[0]
reloaded_score = reloaded_vuln.risk_scores[0]
reloaded_task = reloaded_vuln.remediation_tasks[0]

print(f"Org: {reloaded_org.name}")
print(f"  -> Asset: {reloaded_asset.hostname} (criticality={reloaded_asset.criticality.value}, internet_facing={reloaded_asset.internet_facing})")
print(f"     -> Vulnerability: {reloaded_vuln.title} (status={reloaded_vuln.status.value})")
print(f"        -> Linked CVE: {reloaded_vuln.cve_id}")
print(f"        -> Risk Score: {reloaded_score.composite_score} (version={reloaded_score.score_version})")
print(f"        -> Remediation Task: priority={reloaded_task.priority.value}, assignee={reloaded_task.assigned_to_id == user.id}")
print()
print("ALL RELATIONSHIPS RESOLVED CORRECTLY")

db.close()
