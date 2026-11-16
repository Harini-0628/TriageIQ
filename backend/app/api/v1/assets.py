from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.models.asset import AssetCriticality, Environment, Asset
from app.api.v1.deps import get_current_user, require_roles
from app.schemas.asset import AssetOut, AssetCreate, AssetUpdate
from app.repositories.asset_repository import AssetRepository
from app.repositories.audit_log_repository import write_audit_log

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=List[AssetOut])
def list_assets(
    criticality: Optional[AssetCriticality] = None,
    environment: Optional[Environment] = None,
    internet_facing: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = AssetRepository(db).list_with_open_vuln_counts(
        current_user.org_id, criticality=criticality, environment=environment,
        internet_facing=internet_facing, search=search,
    )
    return [
        AssetOut.model_validate(asset).model_copy(update={"open_vulnerability_count": count})
        for asset, count in rows
    ]


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    asset = AssetRepository(db).get_by_id(current_user.org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    open_count = (
        db.query(Vulnerability)
        .filter(Vulnerability.asset_id == asset.id, Vulnerability.status.in_([VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]))
        .count()
    )
    return AssetOut.model_validate(asset).model_copy(update={"open_vulnerability_count": open_count})


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    repo = AssetRepository(db)
    if repo.get_by_hostname(current_user.org_id, payload.hostname):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An asset with this hostname already exists")

    asset = repo.create(Asset(org_id=current_user.org_id, **payload.model_dump()))
    write_audit_log(db, current_user.org_id, current_user.id, "asset.created", "asset", asset.id,
                     details={"hostname": asset.hostname})
    db.commit()
    return asset


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    repo = AssetRepository(db)
    asset = repo.get_by_id(current_user.org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    changes = payload.model_dump(exclude_unset=True)
    before = {field: getattr(asset, field).value if hasattr(getattr(asset, field), "value") else getattr(asset, field) for field in changes}
    for field, value in changes.items():
        setattr(asset, field, value)

    # Asset criticality/exposure directly feed the risk formula (Module 6) —
    # this is exactly the kind of change that's worth an explicit audit
    # entry: "why did this vulnerability's risk score suddenly change?"
    # traces back to an asset edit, not a mystery.
    write_audit_log(db, current_user.org_id, current_user.id, "asset.updated", "asset", asset.id,
                     details={"before": before, "after": changes})
    db.commit()
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),  # deleting an asset (and cascading its findings) is admin-only
):
    repo = AssetRepository(db)
    asset = repo.get_by_id(current_user.org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    write_audit_log(db, current_user.org_id, current_user.id, "asset.deleted", "asset", asset.id,
                     details={"hostname": asset.hostname})
    repo.delete(asset)
    db.commit()
