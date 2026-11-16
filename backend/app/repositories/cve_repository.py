"""
CVE repository. At import time we only know a CVE ID exists — we don't
yet know its CVSS/EPSS/KEV data (that's Module 5's enrichment pipeline).
Creating a bare-minimum CVE row now means the Vulnerability foreign key
has something valid to point at immediately, and the enrichment job can
find "CVEs with no enrichment_fetched_at yet" as its work queue later.
"""
from typing import Optional

from sqlalchemy.orm import Session

from app.models.cve import CVE


class CVERepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, cve_id: str) -> Optional[CVE]:
        return self.db.query(CVE).filter(CVE.cve_id == cve_id).first()

    def get_or_create_stub(self, cve_id: str) -> CVE:
        existing = self.get(cve_id)
        if existing:
            return existing
        stub = CVE(cve_id=cve_id)  # all enrichment fields nullable, filled in by Module 5
        self.db.add(stub)
        self.db.flush()
        return stub
