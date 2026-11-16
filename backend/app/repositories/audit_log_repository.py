"""
Audit log write helper.

Design decision: this is the ONLY place in the codebase that writes an
AuditLog row, and every state-changing endpoint in this module (status
changes, remediation task updates) calls it. Centralizing the write means
"what fields does an audit entry need" gets answered once, not
reimplemented slightly differently at each call site — which is exactly
how audit trails silently end up inconsistent in real systems.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.report_audit_notification import AuditLog


def write_audit_log(
    db: Session,
    org_id: str,
    user_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: str,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    entry = AuditLog(
        org_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.flush()
    return entry
