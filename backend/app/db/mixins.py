"""
Shared model mixins.

Design decision: UUID primary keys (not auto-increment integers) because
this is a multi-tenant security product. Sequential integer IDs leak
information (an attacker who sees vulnerability id=4102 can guess how many
vulnerabilities exist, or enumerate /vulnerabilities/1, /2, /3...). UUIDs
close that enumeration/IDOR vector by default.

We store UUIDs as String(36) rather than a Postgres-only UUID column type
so the exact same model works against both Postgres (prod/staging) and
SQLite (fast local dev/tests) without branching code.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UUIDMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
