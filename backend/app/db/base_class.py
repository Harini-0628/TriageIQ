"""
Declarative base for all ORM models.

Design decision: a single shared Base (rather than each model importing
its own) is required for Alembic autogenerate to see every table when it
diffs metadata against the live database.
"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
