from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.remediation import TaskStatus, TaskPriority

# SLA defaults by priority — a real vuln management program is graded on
# adherence to numbers like these (e.g. "critical vulns patched within 15
# days"). Configurable-per-org SLA policy is a reasonable future module;
# these are sane, commonly-used industry defaults for a fresher portfolio.
DEFAULT_SLA_DAYS = {
    TaskPriority.P1_CRITICAL: 15,
    TaskPriority.P2_HIGH: 30,
    TaskPriority.P3_MEDIUM: 60,
    TaskPriority.P4_LOW: 90,
}


class RemediationTaskCreate(BaseModel):
    priority: TaskPriority
    assigned_to_id: Optional[str] = None
    sla_days: Optional[int] = None  # if omitted, defaults from DEFAULT_SLA_DAYS based on priority
    notes: Optional[str] = None


class RemediationTaskUpdate(BaseModel):
    status: Optional[TaskStatus] = None
    assigned_to_id: Optional[str] = None
    notes: Optional[str] = None


class RemediationTaskOut(BaseModel):
    id: str
    vulnerability_id: str
    vulnerability_title: str
    assigned_to_id: Optional[str]
    assigned_to_name: Optional[str]
    status: TaskStatus
    priority: TaskPriority
    sla_days: int
    due_date: datetime
    is_overdue: bool
    resolved_at: Optional[datetime]
    notes: Optional[str]
    created_at: datetime
