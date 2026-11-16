"""
User model.

Design decision: role is a Python Enum stored as a SQLAlchemy Enum, not a
free-text string. This means invalid roles are rejected at the database
level, not just the application level — defense in depth. RBAC here is
intentionally simple (3 roles) because real RBAC complexity (fine-grained
permissions per resource) belongs in Module 3's authorization layer, not
baked into the schema.
"""
import enum
from typing import Optional

from sqlalchemy import String, Boolean, ForeignKey, DateTime
from app.db.enum_utils import str_enum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base
from app.db.mixins import UUIDMixin, TimestampMixin


class UserRole(str, enum.Enum):
    ADMIN = "admin"       # full org control: manage users, integrations, delete data
    ANALYST = "analyst"   # import scans, triage, remediate — the primary daily user
    VIEWER = "viewer"     # read-only, for execs/auditors viewing dashboards


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(str_enum(UserRole), default=UserRole.ANALYST, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[Optional[DateTime]] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped["Organization"] = relationship(back_populates="users")
