"""
Pure unit tests for the risk scoring formula. No database, no network —
these run in milliseconds and pin down EXACT expected numbers, which is
the right bar for the single most important piece of logic in the app.
"""
from datetime import datetime, timezone, timedelta

from app.models.asset import AssetCriticality
from app.services.risk_scoring import (
    calculate_cvss_component, calculate_epss_component, calculate_kev_component,
    calculate_asset_criticality_component, calculate_exposure_component,
    calculate_age_component, calculate_risk_components,
)

now = datetime(2026, 7, 15, tzinfo=timezone.utc)

# --- CVSS component ---
assert calculate_cvss_component(10.0) == 30.0
assert calculate_cvss_component(5.0) == 15.0
assert calculate_cvss_component(0.0) == 0.0
assert calculate_cvss_component(None) == 0.0
assert calculate_cvss_component(15.0) == 30.0  # out-of-range input clamped, doesn't blow past the weight
print("PASS: CVSS component — 10.0->30pts, 5.0->15pts, None->0pts, out-of-range clamped")

# --- EPSS component ---
assert calculate_epss_component(1.0) == 25.0
assert calculate_epss_component(0.5) == 12.5
assert calculate_epss_component(0.0) == 0.0
assert calculate_epss_component(None) == 0.0
print("PASS: EPSS component — 1.0->25pts, 0.5->12.5pts, None->0pts")

# --- KEV component ---
assert calculate_kev_component(True, True) == 20.0    # base 15 + ransomware bonus 5, capped at 20
assert calculate_kev_component(True, False) == 15.0
assert calculate_kev_component(True, None) == 15.0
assert calculate_kev_component(False, True) == 0.0     # not in KEV at all -> 0, regardless of ransomware flag
print("PASS: KEV component — in KEV+ransomware->20pts (capped), in KEV only->15pts, not in KEV->0pts")

# --- Asset criticality component ---
assert calculate_asset_criticality_component(AssetCriticality.CRITICAL) == 15.0
assert calculate_asset_criticality_component(AssetCriticality.HIGH) == 10.0
assert calculate_asset_criticality_component(AssetCriticality.MEDIUM) == 5.0
assert calculate_asset_criticality_component(AssetCriticality.LOW) == 0.0
print("PASS: Asset criticality component — critical->15, high->10, medium->5, low->0")

# --- Exposure component ---
assert calculate_exposure_component(True) == 5.0
assert calculate_exposure_component(False) == 0.0
print("PASS: Exposure component — internet-facing->5pts, internal->0pts")

# --- Age component ---
assert calculate_age_component(now - timedelta(days=90), now=now) == 5.0   # exactly at cap
assert calculate_age_component(now - timedelta(days=180), now=now) == 5.0  # beyond cap, still capped at 5
assert calculate_age_component(now - timedelta(days=45), now=now) == 2.5   # halfway
assert calculate_age_component(now, now=now) == 0.0                        # detected today
print("PASS: Age component — 90+ days->5pts (capped), 45 days->2.5pts, 0 days->0pts")

# --- THE critical scenario this whole product is built around ---
# A medium-CVSS finding that's actively exploited (KEV) on a critical,
# internet-facing asset should OUTRANK a critical-CVSS finding sitting on
# a low-criticality internal asset with no real-world exploitation. This
# is the entire premise of risk-based prioritization over raw CVSS.
real_world_risk = calculate_risk_components(
    cvss_v3_score=6.5,               # only "medium" by raw CVSS
    epss_score=0.92,                 # but actively being exploited in the wild
    is_known_exploited=True,
    kev_ransomware_use=True,
    asset_criticality=AssetCriticality.CRITICAL,
    internet_facing=True,
    first_detected_at=now - timedelta(days=10),
    now=now,
)
paper_tiger_risk = calculate_risk_components(
    cvss_v3_score=9.8,                # "critical" by raw CVSS alone
    epss_score=0.01,                  # but essentially never exploited in practice
    is_known_exploited=False,
    kev_ransomware_use=None,
    asset_criticality=AssetCriticality.LOW,
    internet_facing=False,
    first_detected_at=now - timedelta(days=10),
    now=now,
)
assert real_world_risk.composite > paper_tiger_risk.composite, (
    f"Risk-based scoring failed its entire purpose: {real_world_risk.composite} should exceed {paper_tiger_risk.composite}"
)
print(f"PASS: real-world-exploited medium-CVSS finding ({real_world_risk.composite}) correctly "
      f"OUTRANKS a high-CVSS-but-theoretical finding ({paper_tiger_risk.composite}) — "
      f"this is the entire point of the product")

# --- Maximum possible score is exactly 100 ---
max_risk = calculate_risk_components(
    cvss_v3_score=10.0, epss_score=1.0, is_known_exploited=True, kev_ransomware_use=True,
    asset_criticality=AssetCriticality.CRITICAL, internet_facing=True,
    first_detected_at=now - timedelta(days=365), now=now,
)
assert max_risk.composite == 100.0, f"Max score should be exactly 100.0, got {max_risk.composite}"
print(f"PASS: maximum possible composite score is exactly 100.0 (weights sum correctly)")

# --- Minimum possible score is exactly 0 ---
min_risk = calculate_risk_components(
    cvss_v3_score=None, epss_score=None, is_known_exploited=False, kev_ransomware_use=None,
    asset_criticality=AssetCriticality.LOW, internet_facing=False,
    first_detected_at=now, now=now,
)
assert min_risk.composite == 0.0, f"Min score should be exactly 0.0, got {min_risk.composite}"
print(f"PASS: minimum possible composite score (no enrichment data yet, low-criticality internal asset) is exactly 0.0")

print()
print("ALL RISK SCORING FORMULA CHECKS PASSED")
