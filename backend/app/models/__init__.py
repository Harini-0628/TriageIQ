"""
Every model must be imported here. This isn't cosmetic — SQLAlchemy only
registers a model against Base.metadata when its module has been imported
somewhere. If a model is defined but never imported, Alembic's autogenerate
silently won't see it and won't create a migration for it. This file is
the single place that guarantees that doesn't happen.
"""
from app.models.organization import Organization
from app.models.user import User, UserRole
from app.models.asset import Asset, AssetGroup, AssetCriticality, AssetType, Environment
from app.models.cve import CVE
from app.models.vulnerability import Vulnerability, VulnerabilityStatus, ScannerSeverity
from app.models.risk_score import RiskScore
from app.models.remediation import RemediationTask, TaskStatus, TaskPriority
from app.models.scan_import import ScanImport, ScannerType, ImportStatus
from app.models.report_audit_notification import Report, AuditLog, Notification, ReportType, ReportFormat

__all__ = [
    "Organization",
    "User", "UserRole",
    "Asset", "AssetGroup", "AssetCriticality", "AssetType", "Environment",
    "CVE",
    "Vulnerability", "VulnerabilityStatus", "ScannerSeverity",
    "RiskScore",
    "RemediationTask", "TaskStatus", "TaskPriority",
    "ScanImport", "ScannerType", "ImportStatus",
    "Report", "AuditLog", "Notification", "ReportType", "ReportFormat",
]
