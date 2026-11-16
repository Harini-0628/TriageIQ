"""
ScanImport model — tracks the lifecycle of an uploaded Nessus/OpenVAS file.

Design decision: import is modeled as an async-friendly job (status:
processing/completed/failed), not a synchronous request/response. A real
Nessus CSV export can contain tens of thousands of rows — parsing that
inline in an HTTP request would time out. This schema anticipates Module 4
running the actual parse as a background task and lets the frontend poll
or subscribe for progress.
"""
import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import String, ForeignKey, DateTime, Integer
from app.db.enum_utils import str_enum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base
from app.db.mixins import UUIDMixin


class ScannerType(str, enum.Enum):
    NESSUS = "nessus"
    OPENVAS = "openvas"


class ImportStatus(str, enum.Enum):
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanImport(Base, UUIDMixin):
    __tablename__ = "scan_imports"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    uploaded_by_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    scanner_type: Mapped[ScannerType] = mapped_column(str_enum(ScannerType), nullable=False)
    status: Mapped[ImportStatus] = mapped_column(str_enum(ImportStatus), default=ImportStatus.UPLOADED, nullable=False)

    total_rows: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    findings_created: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    assets_created: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)

    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
