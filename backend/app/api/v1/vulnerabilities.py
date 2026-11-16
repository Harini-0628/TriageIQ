from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.models.vulnerability import VulnerabilityStatus, ScannerSeverity
from app.api.v1.deps import get_current_user, require_roles
from app.schemas.vulnerability import VulnerabilityOut, VulnerabilityListItem, VulnerabilityUpdate
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.repositories.audit_log_repository import write_audit_log

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=List[VulnerabilityListItem])
def list_vulnerabilities(
    status_filter: Optional[VulnerabilityStatus] = None,
    severity: Optional[ScannerSeverity] = None,
    asset_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = VulnerabilityRepository(db).list_with_latest_score(
        current_user.org_id, status=status_filter, severity=severity, asset_id=asset_id, search=search,
    )
    return [
        VulnerabilityListItem(
            id=vuln.id, asset_hostname=asset.hostname, cve_id=vuln.cve_id, title=vuln.title,
            scanner_severity=vuln.scanner_severity, status=vuln.status,
            latest_risk_score=score, last_detected_at=vuln.last_detected_at,
        )
        for vuln, asset, score in rows
    ]


@router.get("/{vulnerability_id}", response_model=VulnerabilityOut)
def get_vulnerability(vulnerability_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    repo = VulnerabilityRepository(db)
    vuln = repo.get_by_id(current_user.org_id, vulnerability_id)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    return VulnerabilityOut(
        id=vuln.id, asset_id=vuln.asset_id, asset_hostname=vuln.asset.hostname, cve_id=vuln.cve_id,
        title=vuln.title, description=vuln.description, scanner_severity=vuln.scanner_severity,
        status=vuln.status, port=vuln.port, protocol=vuln.protocol,
        latest_risk_score=repo.get_latest_score(vuln.id),
        first_detected_at=vuln.first_detected_at, last_detected_at=vuln.last_detected_at,
    )


@router.patch("/{vulnerability_id}", response_model=VulnerabilityOut)
def update_vulnerability_status(
    vulnerability_id: str,
    payload: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Status changes are the core triage workflow (open -> in_progress ->
    remediated / accepted_risk / false_positive). Every change is audit
    logged with the old status, new status, who made it, and why — this
    is precisely the kind of trail a GRC/compliance audit asks for, and
    precisely why AuditLog exists as its own table rather than just an
    updated_at timestamp.
    """
    repo = VulnerabilityRepository(db)
    vuln = repo.get_by_id(current_user.org_id, vulnerability_id)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    old_status = vuln.status
    vuln.status = payload.status

    write_audit_log(
        db, current_user.org_id, current_user.id, "vulnerability.status_changed", "vulnerability", vuln.id,
        details={"from": old_status.value, "to": payload.status.value, "reason": payload.reason},
    )
    db.commit()

    return VulnerabilityOut(
        id=vuln.id, asset_id=vuln.asset_id, asset_hostname=vuln.asset.hostname, cve_id=vuln.cve_id,
        title=vuln.title, description=vuln.description, scanner_severity=vuln.scanner_severity,
        status=vuln.status, port=vuln.port, protocol=vuln.protocol,
        latest_risk_score=repo.get_latest_score(vuln.id),
        first_detected_at=vuln.first_detected_at, last_detected_at=vuln.last_detected_at,
    )
