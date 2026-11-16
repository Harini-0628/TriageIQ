from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.models.vulnerability import Vulnerability
from app.api.v1.deps import get_current_user, require_roles
from app.schemas.risk import RankedVulnerabilityOut, RiskScoreHistoryOut, RecalculationSummaryOut
from app.services.risk_engine_service import recalculate_for_org, get_ranked_queue
from app.repositories.risk_score_repository import RiskScoreRepository

router = APIRouter(prefix="/risk", tags=["risk"])


@router.post("/recalculate", response_model=RecalculationSummaryOut)
def recalculate(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    summary = recalculate_for_org(db, current_user.org_id)
    return RecalculationSummaryOut(
        vulnerabilities_scored=summary.vulnerabilities_scored,
        highest_score=summary.highest_score,
        highest_score_title=summary.highest_score_title,
    )


@router.get("/queue", response_model=List[RankedVulnerabilityOut])
def ranked_queue(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The prioritized remediation queue — the core value of the product."""
    return get_ranked_queue(db, current_user.org_id, limit=limit)


@router.get("/vulnerabilities/{vulnerability_id}/history", response_model=List[RiskScoreHistoryOut])
def score_history(
    vulnerability_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == vulnerability_id, Vulnerability.org_id == current_user.org_id)
        .first()
    )
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    return RiskScoreRepository(db).get_history_for_vulnerability(vulnerability_id)
