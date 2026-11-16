"""
RemediationTask model — closes the loop from "detected" to "fixed."

Design decision: SLA tracking (sla_days + due_date) is what turns this from
a passive list into an accountable workflow tool. Real vuln management
programs are graded on SLA adherence (e.g. "critical vulns must be patched
within 15 days") — a dashboard showing SLA breach rate is exactly the kind
of executive-facing metric that makes this look like a real product.
"""
import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import String, ForeignKey, DateTime, Integer
from app.db.enum_utils import str_enum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.db.mixins import UUIDMixin, TimestampMixin


class TaskStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    RESOLVED = "resolved"
    VERIFIED = "verified"  # resolved AND confirmed by a re-scan — a common real-world extra step


class TaskPriority(str, enum.Enum):
    P1_CRITICAL = "p1_critical"
    P2_HIGH = "p2_high"
    P3_MEDIUM = "p3_medium"
    P4_LOW = "p4_low"


class RemediationTask(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_tasks"

    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    assigned_to_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    status: Mapped[TaskStatus] = mapped_column(str_enum(TaskStatus), default=TaskStatus.OPEN, nullable=False, index=True)
    priority: Mapped[TaskPriority] = mapped_column(str_enum(TaskPriority), nullable=False)

    sla_days: Mapped[int] = mapped_column(Integer, nullable=False)  # e.g. 15 for critical, 90 for low
    due_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    notes: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="remediation_tasks")
    assigned_to: Mapped[Optional["User"]] = relationship()
