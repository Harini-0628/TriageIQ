"""
Pydantic schemas for the auth API.

Design decision: these are entirely separate from the SQLAlchemy models in
app/models/. Request/response shape and database table shape are different
concerns that change for different reasons (e.g. we never want
hashed_password to be *possible* to serialize into a response — keeping
schemas separate makes that a structural guarantee, not a "don't forget"
discipline problem).
"""
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import UserRole


class RegisterRequest(BaseModel):
    organization_name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        # Deliberately simple, readable rules — NIST 800-63B actually
        # recommends length over forced complexity (no more "must contain
        # a symbol" theater), so we enforce length + basic variety only.
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c.isalpha() for c in v):
            raise ValueError("Password must contain at least one letter")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: str
    org_id: str
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool

    model_config = {"from_attributes": True}  # allows UserOut.model_validate(sqlalchemy_user_instance)
