"""
RiskScore model.

Design decision: this is a HISTORY table (many rows per vulnerability over
time), not a single column bolted onto Vulnerability. Risk scores change
as EPSS updates daily, KEV status changes, or an asset's criticality is
reclassified. Keeping history is what enables "historical trend analysis"
and lets us show "this vulnerability's risk score jumped from 42 to 91
last Tuesday because it was just added to CISA KEV" — a genuinely
compelling thing to demo live in an interview.

score_version lets us change the scoring formula later (Module 6) without
losing the ability to explain which formula produced an old score.
"""
from datetime import datetime

from sqlalchemy import Float, ForeignKey, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.db.mixins import UUIDMixin


class RiskScore(Base, UUIDMixin):
    __tablename__ = "risk_scores"

    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )

    composite_score: Mapped[float] = mapped_column(Float, nullable=False)  # final 0-100 score

    # Individual weighted components — stored separately so the UI can show
    # "why is this scored 87?" as a breakdown, not just a black-box number.
    cvss_component: Mapped[float] = mapped_column(Float, nullable=False)
    epss_component: Mapped[float] = mapped_column(Float, nullable=False)
    kev_component: Mapped[float] = mapped_column(Float, nullable=False)
    asset_criticality_component: Mapped[float] = mapped_column(Float, nullable=False)
    exposure_component: Mapped[float] = mapped_column(Float, nullable=False)
    age_component: Mapped[float] = mapped_column(Float, nullable=False)

    score_version: Mapped[str] = mapped_column(String(20), default="v1", nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="risk_scores")
