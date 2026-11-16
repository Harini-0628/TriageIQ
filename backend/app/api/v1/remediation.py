from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.models.remediation import RemediationTask, TaskStatus, TaskPriority
from app.api.v1.deps import get_current_user, require_roles
from app.schemas.remediation import RemediationTaskCreate, RemediationTaskUpdate, RemediationTaskOut, DEFAULT_SLA_DAYS
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.remediation_task_repository import RemediationTaskRepository
from app.repositories.audit_log_repository import write_audit_log

router = APIRouter(tags=["remediation"])


def _to_out(task: RemediationTask, vuln_title: str, assignee_name: Optional[str]) -> RemediationTaskOut:
    now = datetime.now(timezone.utc)
    due = task.due_date if task.due_date.tzinfo else task.due_date.replace(tzinfo=timezone.utc)
    is_overdue = due < now and task.status not in (TaskStatus.RESOLVED, TaskStatus.VERIFIED)
    return RemediationTaskOut(
        id=task.id, vulnerability_id=task.vulnerability_id, vulnerability_title=vuln_title,
        assigned_to_id=task.assigned_to_id, assigned_to_name=assignee_name,
        status=task.status, priority=task.priority, sla_days=task.sla_days,
        due_date=task.due_date, is_overdue=is_overdue, resolved_at=task.resolved_at,
        notes=task.notes, created_at=task.created_at,
    )


@router.post("/vulnerabilities/{vulnerability_id}/remediation-tasks", response_model=RemediationTaskOut, status_code=status.HTTP_201_CREATED)
def create_remediation_task(
    vulnerability_id: str,
    payload: RemediationTaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    vuln_repo = VulnerabilityRepository(db)
    vuln = vuln_repo.get_by_id(current_user.org_id, vulnerability_id)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    sla_days = payload.sla_days or DEFAULT_SLA_DAYS[payload.priority]
    now = datetime.now(timezone.utc)
    task = RemediationTask(
        vulnerability_id=vuln.id,
        assigned_to_id=payload.assigned_to_id,
        status=TaskStatus.OPEN,
        priority=payload.priority,
        sla_days=sla_days,
        due_date=now + timedelta(days=sla_days),
        notes=payload.notes,
    )
    RemediationTaskRepository(db).create(task)

    # Triaging a finding into active remediation is exactly the moment a
    # GRC audit cares about — "when was this risk formally assigned, to
    # whom, with what SLA."
    write_audit_log(db, current_user.org_id, current_user.id, "remediation_task.created", "remediation_task", task.id,
                     details={"vulnerability_id": vuln.id, "priority": payload.priority.value, "sla_days": sla_days})
    db.commit()

    assignee_name = task.assigned_to.full_name if task.assigned_to_id and task.assigned_to else None
    return _to_out(task, vuln.title, assignee_name)


@router.get("/remediation-tasks", response_model=List[RemediationTaskOut])
def list_remediation_tasks(
    status_filter: Optional[TaskStatus] = None,
    assigned_to_me: bool = False,
    overdue_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo = RemediationTaskRepository(db)
    assigned_to_id = current_user.id if assigned_to_me else None
    rows = repo.list_with_details(current_user.org_id, status=status_filter, assigned_to_id=assigned_to_id, overdue_only=overdue_only)
    return [_to_out(task, vuln_title, assignee_name) for task, vuln_title, assignee_name in rows]


@router.patch("/remediation-tasks/{task_id}", response_model=RemediationTaskOut)
def update_remediation_task(
    task_id: str,
    payload: RemediationTaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    repo = RemediationTaskRepository(db)
    task = repo.get_by_id(current_user.org_id, task_id)
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation task not found")

    changes = payload.model_dump(exclude_unset=True)
    old_status = task.status

    for field, value in changes.items():
        setattr(task, field, value)

    if "status" in changes and changes["status"] == TaskStatus.RESOLVED and old_status != TaskStatus.RESOLVED:
        task.resolved_at = datetime.now(timezone.utc)

    write_audit_log(db, current_user.org_id, current_user.id, "remediation_task.updated", "remediation_task", task.id,
                     details={"changes": {k: (v.value if hasattr(v, "value") else v) for k, v in changes.items()}})
    db.commit()

    vuln_title = task.vulnerability.title
    assignee_name = task.assigned_to.full_name if task.assigned_to_id and task.assigned_to else None
    return _to_out(task, vuln_title, assignee_name)
