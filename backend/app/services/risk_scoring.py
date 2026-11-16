"""
Composite risk scoring — the core intellectual property of this product.

Design decision: every function here is PURE (plain values in, a float
out, no database, no ORM, no I/O). This is deliberate: the scoring
formula is the single most important piece of logic in the entire
codebase, and it needs to be trivially unit-testable with exact expected
numbers — not something you can only verify by standing up a database and
eyeballing a dashboard. `RiskEngineService` (below) is the thin layer that
pulls real Vulnerability/CVE/Asset rows and calls these functions; this
file has no idea a database exists.

=== The formula ===

composite_score (0-100) = cvss_component + epss_component + kev_component
                         + asset_criticality_component + exposure_component
                         + age_component

Weights (why raw CVSS alone is a bad prioritization signal — this is the
entire premise of the product):

  CVSS               30 pts  — "how bad IS this vulnerability, in isolation"
  EPSS               25 pts  — "how likely is this to actually be exploited
                                in the next 30 days" (CVSS says nothing
                                about this — a 9.8 CVSS with near-zero EPSS
                                is usually the WRONG thing to patch first)
  CISA KEV           20 pts  — "is this being exploited RIGHT NOW, confirmed
                                by CISA" — the single highest-confidence
                                signal available, weighted accordingly
  Asset criticality  15 pts  — "does this matter to the business" — the
                                same CVE on a throwaway dev box vs. the
                                production auth service is not the same risk
  Internet exposure   5 pts  — "can an attacker even reach this"
  Vulnerability age   5 pts  — "how long has this sat open" — a small but
                                real staleness signal; an old open critical
                                finding indicates a process failure worth
                                surfacing

Weights sum to exactly 100, so a maximal finding (10.0 CVSS, EPSS=1.0,
in KEV with ransomware use, on a critical internet-facing asset, open 90+
days) scores exactly 100.0 — verified in tests/verify_risk_scoring.py.
"""
from datetime import datetime, timezone
from typing import Optional

from app.models.asset import AssetCriticality

SCORE_VERSION = "v1"

CVSS_WEIGHT = 30.0
EPSS_WEIGHT = 25.0
KEV_BASE_WEIGHT = 15.0
KEV_RANSOMWARE_BONUS = 5.0
KEV_MAX_WEIGHT = 20.0
ASSET_CRITICALITY_WEIGHTS = {
    AssetCriticality.CRITICAL: 15.0,
    AssetCriticality.HIGH: 10.0,
    AssetCriticality.MEDIUM: 5.0,
    AssetCriticality.LOW: 0.0,
}
EXPOSURE_WEIGHT = 5.0
AGE_WEIGHT = 5.0
AGE_MAX_DAYS = 90  # a finding open 90+ days maxes out the staleness component


def calculate_cvss_component(cvss_v3_score: Optional[float]) -> float:
    """No CVSS data (enrichment hasn't run yet, or NVD has no record) scores
    0 here rather than raising — a partially-enriched finding must still
    produce a usable (if lower-confidence) score, not crash the whole run."""
    if cvss_v3_score is None:
        return 0.0
    return round((max(0.0, min(cvss_v3_score, 10.0)) / 10.0) * CVSS_WEIGHT, 2)


def calculate_epss_component(epss_score: Optional[float]) -> float:
    if epss_score is None:
        return 0.0
    return round(max(0.0, min(epss_score, 1.0)) * EPSS_WEIGHT, 2)


def calculate_kev_component(is_known_exploited: bool, kev_ransomware_use: Optional[bool]) -> float:
    if not is_known_exploited:
        return 0.0
    score = KEV_BASE_WEIGHT
    if kev_ransomware_use:
        score += KEV_RANSOMWARE_BONUS
    return round(min(score, KEV_MAX_WEIGHT), 2)


def calculate_asset_criticality_component(criticality: AssetCriticality) -> float:
    return ASSET_CRITICALITY_WEIGHTS[criticality]


def calculate_exposure_component(internet_facing: bool) -> float:
    return EXPOSURE_WEIGHT if internet_facing else 0.0


def calculate_age_component(first_detected_at: datetime, now: Optional[datetime] = None) -> float:
    now = now or datetime.now(timezone.utc)
    # first_detected_at from the DB may be naive (SQLite doesn't preserve
    # tzinfo) — normalize both sides to naive UTC before subtracting, or a
    # naive-vs-aware datetime subtraction raises TypeError at exactly the
    # worst time (mid risk-recalculation run).
    fd = first_detected_at.replace(tzinfo=None) if first_detected_at.tzinfo else first_detected_at
    now_naive = now.replace(tzinfo=None) if now.tzinfo else now
    days_open = max(0, (now_naive - fd).days)
    fraction = min(days_open / AGE_MAX_DAYS, 1.0)
    return round(fraction * AGE_WEIGHT, 2)


class RiskComponents:
    """Holds the breakdown, not just the total — the UI needs to answer
    'why is this scored 87?' as a visible breakdown, not a black box."""

    def __init__(
        self,
        cvss: float, epss: float, kev: float,
        asset_criticality: float, exposure: float, age: float,
    ):
        self.cvss = cvss
        self.epss = epss
        self.kev = kev
        self.asset_criticality = asset_criticality
        self.exposure = exposure
        self.age = age

    @property
    def composite(self) -> float:
        total = self.cvss + self.epss + self.kev + self.asset_criticality + self.exposure + self.age
        return round(min(total, 100.0), 2)


def calculate_risk_components(
    cvss_v3_score: Optional[float],
    epss_score: Optional[float],
    is_known_exploited: bool,
    kev_ransomware_use: Optional[bool],
    asset_criticality: AssetCriticality,
    internet_facing: bool,
    first_detected_at: datetime,
    now: Optional[datetime] = None,
) -> RiskComponents:
    return RiskComponents(
        cvss=calculate_cvss_component(cvss_v3_score),
        epss=calculate_epss_component(epss_score),
        kev=calculate_kev_component(is_known_exploited, kev_ransomware_use),
        asset_criticality=calculate_asset_criticality_component(asset_criticality),
        exposure=calculate_exposure_component(internet_facing),
        age=calculate_age_component(first_detected_at, now),
    )
