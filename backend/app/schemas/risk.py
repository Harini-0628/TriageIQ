from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RankedVulnerabilityOut(BaseModel):
    vulnerability_id: str
    title: str
    cve_id: Optional[str]
    asset_hostname: str
    asset_criticality: str
    status: str
    composite_score: float
    cvss_component: float
    epss_component: float
    kev_component: float
    asset_criticality_component: float
    exposure_component: float
    age_component: float
    calculated_at: datetime


class RiskScoreHistoryOut(BaseModel):
    composite_score: float
    cvss_component: float
    epss_component: float
    kev_component: float
    asset_criticality_component: float
    exposure_component: float
    age_component: float
    score_version: str
    calculated_at: datetime

    model_config = {"from_attributes": True}


class RecalculationSummaryOut(BaseModel):
    vulnerabilities_scored: int
    highest_score: float
    highest_score_title: Optional[str]
