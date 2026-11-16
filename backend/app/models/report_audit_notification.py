"""
Report, AuditLog, Notification models.

AuditLog design decision: this is append-only by convention (the app layer
never issues UPDATE/DELETE against it) because an audit trail that can be
edited isn't an audit trail — this matters a lot in GRC/compliance
contexts and is exactly the kind of thing an interviewer will probe on
("how do you know your audit log itself wasn't tampered with?").
"""
import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import String, ForeignKey, DateTime, Boolean, JSON
from app.db.enum_utils import str_enum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base
from app.db.mixins import UUIDMixin


class ReportType(str, enum.Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    CSV = "csv"


class Report(Base, UUIDMixin):
    __tablename__ = "reports"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    generated_by_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    report_type: Mapped[ReportType] = mapped_column(str_enum(ReportType), nullable=False)
    format: Mapped[ReportFormat] = mapped_column(str_enum(ReportFormat), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    filters_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # what filters produced this report, for reproducibility

    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditLog(Base, UUIDMixin):
    __tablename__ = "audit_logs"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    action: Mapped[str] = mapped_column(String(100), nullable=False)          # e.g. "vulnerability.status_changed"
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)   # e.g. "vulnerability"
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)      # before/after values, etc.
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Notification(Base, UUIDMixin):
    __tablename__ = "notifications"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    type: Mapped[str] = mapped_column(String(50), nullable=False)   # e.g. "sla_breach", "new_kev_match"
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(String(1000), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
