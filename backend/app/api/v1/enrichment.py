"""
Manual enrichment trigger. A scheduled version of this (running nightly,
refreshing EPSS even for already-enriched CVEs since it changes daily)
belongs in Module 9. This endpoint is the synchronous, on-demand version —
useful right after a scan import, and useful to demo live in an interview
("watch this CVE go from a bare ID to a fully scored entry in real time").
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.api.v1.deps import require_roles
from app.services.enrichment_service import get_cves_needing_enrichment, run_enrichment

router = APIRouter(prefix="/enrichment", tags=["enrichment"])


@router.post("/run")
def trigger_enrichment(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    cves = get_cves_needing_enrichment(db)
    summary = run_enrichment(db, cves)
    return {
        "cves_processed": summary.cves_processed,
        "nvd_enriched": summary.nvd_enriched,
        "epss_enriched": summary.epss_enriched,
        "kev_matches": summary.kev_matches,
        "nvd_not_found": summary.nvd_not_found,
    }
