from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.asset import AssetType, AssetCriticality, Environment


class AssetCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: Optional[str] = None
    asset_type: AssetType = AssetType.SERVER
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    environment: Environment = Environment.PRODUCTION
    internet_facing: bool = False
    owner: Optional[str] = None


class AssetUpdate(BaseModel):
    # All optional — PATCH semantics: only fields the client sends get changed.
    criticality: Optional[AssetCriticality] = None
    environment: Optional[Environment] = None
    internet_facing: Optional[bool] = None
    owner: Optional[str] = None
    ip_address: Optional[str] = None


class AssetOut(BaseModel):
    id: str
    hostname: str
    ip_address: Optional[str]
    asset_type: AssetType
    criticality: AssetCriticality
    environment: Environment
    internet_facing: bool
    owner: Optional[str]
    open_vulnerability_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}
