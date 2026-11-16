"""
CVE model — deliberately NOT org-scoped.

Design decision: a CVE (e.g. CVE-2024-3400) means the same thing for every
tenant. Storing one global, shared record per CVE (rather than copying
NVD/EPSS/KEV data into every org's namespace) avoids massive duplication
and lets a single scheduled job (Module 9) refresh enrichment data for
every org at once. This is standard practice in real vuln-management
products — threat intel is shared, exposure is tenant-specific.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Float, Boolean, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base


class CVE(Base):
    __tablename__ = "cves"

    # The CVE ID itself (e.g. "CVE-2024-3400") is a stable natural key —
    # using it directly as the primary key avoids an extra join/lookup
    # every time we enrich a vulnerability finding.
    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)

    description: Mapped[Optional[str]] = mapped_column(String(4000), nullable=True)

    # --- CVSS (from NVD) ---
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cvss_v3_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # LOW/MEDIUM/HIGH/CRITICAL

    # --- EPSS (from FIRST.org) ---
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)       # 0.0-1.0 probability of exploitation in next 30 days
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # relative rank vs all other CVEs

    # --- CISA KEV (Known Exploited Vulnerabilities) ---
    is_known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_date_added: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_ransomware_use: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Raw upstream payloads kept for audit/debugging — if our parsing logic
    # has a bug later, we can re-derive fields without re-calling the API.
    raw_nvd_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    enrichment_fetched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
