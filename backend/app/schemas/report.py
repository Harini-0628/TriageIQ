from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.report_audit_notification import ReportType, ReportFormat


class ReportOut(BaseModel):
    id: str
    report_type: ReportType
    format: ReportFormat
    generated_at: datetime

    model_config = {"from_attributes": True}
