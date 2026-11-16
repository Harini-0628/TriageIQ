from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.api.v1.deps import get_current_user
from app.schemas.dashboard import DashboardSummaryOut
from app.services.dashboard_service import get_dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryOut)
def dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return get_dashboard_summary(db, current_user.org_id)
