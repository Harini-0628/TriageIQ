"""
Organization = the tenant boundary.

Every other model (except CVE, which is global threat-intel data shared
across all tenants) has an org_id foreign key. This is what makes the
product multi-tenant SaaS-ready rather than single-company-only: a real
buyer expects to onboard their org without touching anyone else's data.
"""
from typing import List

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.db.mixins import UUIDMixin, TimestampMixin


class Organization(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)

    users: Mapped[List["User"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    assets: Mapped[List["Asset"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
