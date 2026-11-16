"""
Asset & AssetGroup models.

Design decision: asset 'criticality' and 'internet_facing' live directly
on the asset, because they are the two single biggest inputs into the
composite risk score (Module 6) — a critical, internet-facing asset with
a medium-severity CVE can outrank a low-criticality internal asset with a
critical CVE. This is the entire premise of risk-based prioritization
over raw CVSS.
"""
import enum
from typing import List, Optional

from sqlalchemy import String, Boolean, ForeignKey
from app.db.enum_utils import str_enum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.db.mixins import UUIDMixin, TimestampMixin


class AssetCriticality(str, enum.Enum):
    CRITICAL = "critical"   # e.g. prod DB, auth service, payment gateway
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetType(str, enum.Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    CLOUD_RESOURCE = "cloud_resource"
    NETWORK_DEVICE = "network_device"
    CONTAINER = "container"


class Environment(str, enum.Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"


class AssetGroup(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "asset_groups"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    assets: Mapped[List["Asset"]] = relationship(back_populates="group")


class Asset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "assets"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id: Mapped[Optional[str]] = mapped_column(ForeignKey("asset_groups.id", ondelete="SET NULL"), nullable=True)

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # 45 chars fits IPv6
    asset_type: Mapped[AssetType] = mapped_column(str_enum(AssetType), nullable=False)
    criticality: Mapped[AssetCriticality] = mapped_column(str_enum(AssetCriticality), default=AssetCriticality.MEDIUM, nullable=False)
    environment: Mapped[Environment] = mapped_column(str_enum(Environment), default=Environment.PRODUCTION, nullable=False)
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # team or individual responsible

    organization: Mapped["Organization"] = relationship(back_populates="assets")
    group: Mapped[Optional["AssetGroup"]] = relationship(back_populates="assets")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
