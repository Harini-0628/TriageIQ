"""
Asset repository — the get_or_create here is the entire dedup story for
assets: a hostname seen across five separate scan uploads over three
months must resolve to the SAME Asset row every time, or the whole
"historical trend" feature (Module 6+) falls apart because each scan
would create a phantom duplicate host.
"""
from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset, AssetType, AssetCriticality, Environment
from app.models.vulnerability import Vulnerability, VulnerabilityStatus


class AssetRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_hostname(self, org_id: str, hostname: str) -> Optional[Asset]:
        # Case-insensitive match — "PROD-API-01" and "prod-api-01" from two
        # different scanner configs must not become two different assets.
        return (
            self.db.query(Asset)
            .filter(Asset.org_id == org_id, func.lower(Asset.hostname) == hostname.lower())
            .first()
        )

    def get_by_id(self, org_id: str, asset_id: str) -> Optional[Asset]:
        return self.db.query(Asset).filter(Asset.id == asset_id, Asset.org_id == org_id).first()

    def list_with_open_vuln_counts(
        self, org_id: str,
        criticality: Optional[AssetCriticality] = None,
        environment: Optional[Environment] = None,
        internet_facing: Optional[bool] = None,
        search: Optional[str] = None,
    ) -> List[tuple]:
        """Returns (Asset, open_vuln_count) tuples — the count is what makes
        an asset list actually useful ("which hosts have the most open
        findings") rather than just a static inventory table."""
        open_count_subq = (
            self.db.query(
                Vulnerability.asset_id,
                func.count(Vulnerability.id).label("open_count"),
            )
            .filter(Vulnerability.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]))
            .group_by(Vulnerability.asset_id)
            .subquery()
        )

        query = (
            self.db.query(Asset, func.coalesce(open_count_subq.c.open_count, 0))
            .outerjoin(open_count_subq, open_count_subq.c.asset_id == Asset.id)
            .filter(Asset.org_id == org_id)
        )
        if criticality:
            query = query.filter(Asset.criticality == criticality)
        if environment:
            query = query.filter(Asset.environment == environment)
        if internet_facing is not None:
            query = query.filter(Asset.internet_facing == internet_facing)
        if search:
            query = query.filter(Asset.hostname.ilike(f"%{search}%"))

        return query.order_by(Asset.hostname).all()

    def create(self, asset: Asset) -> Asset:
        self.db.add(asset)
        self.db.flush()
        return asset

    def delete(self, asset: Asset) -> None:
        self.db.delete(asset)  # cascades to vulnerabilities/risk scores/tasks per the FK ondelete config

    def get_or_create(self, org_id: str, hostname: str, ip_address: Optional[str]) -> tuple[Asset, bool]:
        existing = self.get_by_hostname(org_id, hostname)
        if existing:
            # A newer scan may reveal an IP we didn't have before — fill it
            # in, but never blank out data we already had.
            if ip_address and not existing.ip_address:
                existing.ip_address = ip_address
            return existing, False

        new_asset = Asset(
            org_id=org_id,
            hostname=hostname,
            ip_address=ip_address,
            asset_type=AssetType.SERVER,               # sensible default; editable later via asset management (future module)
            criticality=AssetCriticality.MEDIUM,        # unknown criticality defaults to medium, never silently "low"
            environment=Environment.PRODUCTION,
            internet_facing=False,
        )
        self.db.add(new_asset)
        self.db.flush()
        return new_asset, True
