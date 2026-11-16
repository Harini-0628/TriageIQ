"""
Pure unit tests for the risk scoring formula — no DB, no fixtures needed.
This is the pytest-formalized version of scripts/verify_risk_scoring.py.
"""
from datetime import datetime, timezone, timedelta

import pytest

from app.models.asset import AssetCriticality
from app.services.risk_scoring import (
    calculate_cvss_component, calculate_epss_component, calculate_kev_component,
    calculate_asset_criticality_component, calculate_exposure_component,
    calculate_age_component, calculate_risk_components,
)

NOW = datetime(2026, 7, 15, tzinfo=timezone.utc)


@pytest.mark.parametrize("cvss,expected", [(10.0, 30.0), (5.0, 15.0), (0.0, 0.0), (None, 0.0), (15.0, 30.0)])
def test_cvss_component(cvss, expected):
    assert calculate_cvss_component(cvss) == expected


@pytest.mark.parametrize("epss,expected", [(1.0, 25.0), (0.5, 12.5), (0.0, 0.0), (None, 0.0)])
def test_epss_component(epss, expected):
    assert calculate_epss_component(epss) == expected


@pytest.mark.parametrize("in_kev,ransomware,expected", [
    (True, True, 20.0), (True, False, 15.0), (True, None, 15.0), (False, True, 0.0),
])
def test_kev_component(in_kev, ransomware, expected):
    assert calculate_kev_component(in_kev, ransomware) == expected


@pytest.mark.parametrize("criticality,expected", [
    (AssetCriticality.CRITICAL, 15.0), (AssetCriticality.HIGH, 10.0),
    (AssetCriticality.MEDIUM, 5.0), (AssetCriticality.LOW, 0.0),
])
def test_asset_criticality_component(criticality, expected):
    assert calculate_asset_criticality_component(criticality) == expected


def test_exposure_component():
    assert calculate_exposure_component(True) == 5.0
    assert calculate_exposure_component(False) == 0.0


def test_age_component():
    assert calculate_age_component(NOW - timedelta(days=90), now=NOW) == 5.0
    assert calculate_age_component(NOW - timedelta(days=180), now=NOW) == 5.0  # capped
    assert calculate_age_component(NOW - timedelta(days=45), now=NOW) == 2.5
    assert calculate_age_component(NOW, now=NOW) == 0.0


def test_exploited_medium_cvss_outranks_theoretical_high_cvss():
    """The core scenario this entire product exists to prove: a real-world
    exploited finding must outrank a merely-scary-looking one."""
    real_world_risk = calculate_risk_components(
        cvss_v3_score=6.5, epss_score=0.92, is_known_exploited=True, kev_ransomware_use=True,
        asset_criticality=AssetCriticality.CRITICAL, internet_facing=True,
        first_detected_at=NOW - timedelta(days=10), now=NOW,
    )
    paper_tiger_risk = calculate_risk_components(
        cvss_v3_score=9.8, epss_score=0.01, is_known_exploited=False, kev_ransomware_use=None,
        asset_criticality=AssetCriticality.LOW, internet_facing=False,
        first_detected_at=NOW - timedelta(days=10), now=NOW,
    )
    assert real_world_risk.composite > paper_tiger_risk.composite
    assert real_world_risk.composite == 83.06
    assert paper_tiger_risk.composite == 30.21


def test_max_score_is_exactly_100():
    result = calculate_risk_components(
        cvss_v3_score=10.0, epss_score=1.0, is_known_exploited=True, kev_ransomware_use=True,
        asset_criticality=AssetCriticality.CRITICAL, internet_facing=True,
        first_detected_at=NOW - timedelta(days=365), now=NOW,
    )
    assert result.composite == 100.0


def test_min_score_is_exactly_0():
    result = calculate_risk_components(
        cvss_v3_score=None, epss_score=None, is_known_exploited=False, kev_ransomware_use=None,
        asset_criticality=AssetCriticality.LOW, internet_facing=False,
        first_detected_at=NOW, now=NOW,
    )
    assert result.composite == 0.0
