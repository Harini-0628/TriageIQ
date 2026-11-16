from typing import Dict, List, Optional

from pydantic import BaseModel


class RiskyAssetSummary(BaseModel):
    hostname: str
    criticality: str
    open_vulnerability_count: int
    highest_risk_score: Optional[float]


class SLAComplianceSummary(BaseModel):
    total_tasks: int
    overdue_tasks: int
    compliance_rate: float  # percentage of non-overdue tasks among all open/in-progress tasks


class DashboardSummaryOut(BaseModel):
    total_assets: int
    total_open_vulnerabilities: int
    vulnerabilities_by_severity: Dict[str, int]
    vulnerabilities_by_status: Dict[str, int]
    average_risk_score: Optional[float]
    known_exploited_open_count: int  # open vulns whose CVE is in CISA KEV — the "actively under attack right now" count
    top_risky_assets: List[RiskyAssetSummary]
    sla_compliance: SLAComplianceSummary
