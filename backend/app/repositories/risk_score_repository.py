"""
RiskScore repository. Every recalculation INSERTS a new row rather than
updating an existing one — this is what makes "this vulnerability's score
jumped from 42 to 91 after it was added to KEV" a queryable fact instead
of a value that got silently overwritten.
"""
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.risk_score import RiskScore


class RiskScoreRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, risk_score: RiskScore) -> RiskScore:
        self.db.add(risk_score)
        self.db.flush()
        return risk_score

    def get_latest_for_vulnerability(self, vulnerability_id: str) -> Optional[RiskScore]:
        return (
            self.db.query(RiskScore)
            .filter(RiskScore.vulnerability_id == vulnerability_id)
            .order_by(RiskScore.calculated_at.desc())
            .first()
        )

    def get_history_for_vulnerability(self, vulnerability_id: str) -> List[RiskScore]:
        return (
            self.db.query(RiskScore)
            .filter(RiskScore.vulnerability_id == vulnerability_id)
            .order_by(RiskScore.calculated_at.asc())
            .all()
        )
