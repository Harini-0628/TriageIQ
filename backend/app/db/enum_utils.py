"""
Shared helper for enum columns.

By default, SQLAlchemy's Enum type persists the Python enum member's NAME
(e.g. "ADMIN"), not its .value (e.g. "admin"). For our (str, Enum) classes
that's a trap: every API response, JWT claim, and log line uses .value
("admin"), but the raw database column would silently contain "ADMIN".
That mismatch is invisible until someone runs a raw SQL query or a direct
DB tool against the table and gets confused — exactly the kind of subtle
bug that's worse than a loud one. `str_enum` forces the column to store
.value consistently everywhere.
"""
from typing import Type
from enum import Enum as PyEnum

from sqlalchemy import Enum as SAEnum


def str_enum(enum_cls: Type[PyEnum]) -> SAEnum:
    return SAEnum(enum_cls, values_callable=lambda e: [member.value for member in e])
