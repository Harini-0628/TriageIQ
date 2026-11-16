from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.remediation import RemediationTask, TaskStatus
from app.models.vulnerability import Vulnerability
from app.models.user import User


class RemediationTaskRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, org_id: str, task_id: str) -> Optional[RemediationTask]:
        return (
            self.db.query(RemediationTask)
            .join(Vulnerability, Vulnerability.id == RemediationTask.vulnerability_id)
            .filter(RemediationTask.id == task_id, Vulnerability.org_id == org_id)
            .first()
        )

    def create(self, task: RemediationTask) -> RemediationTask:
        self.db.add(task)
        self.db.flush()
        return task

    def list_with_details(
        self, org_id: str,
        status: Optional[TaskStatus] = None,
        assigned_to_id: Optional[str] = None,
        overdue_only: bool = False,
        limit: int = 100,
    ) -> List[tuple]:
        """Returns (RemediationTask, Vulnerability.title, User.full_name or None) tuples."""
        query = (
            self.db.query(RemediationTask, Vulnerability.title, User.full_name)
            .join(Vulnerability, Vulnerability.id == RemediationTask.vulnerability_id)
            .outerjoin(User, User.id == RemediationTask.assigned_to_id)
            .filter(Vulnerability.org_id == org_id)
        )
        if status:
            query = query.filter(RemediationTask.status == status)
        if assigned_to_id:
            query = query.filter(RemediationTask.assigned_to_id == assigned_to_id)
        if overdue_only:
            now = datetime.now(timezone.utc)
            query = query.filter(
                RemediationTask.due_date < now,
                RemediationTask.status.notin_([TaskStatus.RESOLVED, TaskStatus.VERIFIED]),
            )

        return query.order_by(RemediationTask.due_date.asc()).limit(limit).all()
