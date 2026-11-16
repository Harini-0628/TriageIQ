"""
Repository layer for User/Organization — pure data access, no business
rules. A service (auth_service.py) decides *what* should happen; the
repository only knows *how* to read/write rows. This split is what lets
Module 6's risk-scoring service be unit tested with a fake repository,
with no real database involved.
"""
import re
from typing import Optional

from sqlalchemy.orm import Session

from app.models.user import User
from app.models.organization import Organization


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "org"


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email).first()

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()

    def create(self, user: User) -> User:
        self.db.add(user)
        self.db.flush()
        return user


class OrganizationRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_slug(self, slug: str) -> Optional[Organization]:
        return self.db.query(Organization).filter(Organization.slug == slug).first()

    def create(self, org: Organization) -> Organization:
        self.db.add(org)
        self.db.flush()
        return org

    def unique_slug_for(self, name: str) -> str:
        base = slugify(name)
        slug = base
        counter = 1
        while self.get_by_slug(slug) is not None:
            counter += 1
            slug = f"{base}-{counter}"
        return slug
