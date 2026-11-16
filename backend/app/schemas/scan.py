from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.scan_import import ScannerType, ImportStatus


class ScanImportOut(BaseModel):
    id: str
    filename: str
    scanner_type: ScannerType
    status: ImportStatus
    total_rows: Optional[int]
    findings_created: Optional[int]
    assets_created: Optional[int]
    error_message: Optional[str]
    uploaded_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}
