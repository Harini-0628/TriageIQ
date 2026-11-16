"""
Password hashing + JWT creation/validation.

Design decisions:
- bcrypt (via passlib) for password hashing, never a raw hash (SHA-256 etc).
  bcrypt is deliberately slow and includes a per-password salt automatically,
  which is what makes brute-forcing a stolen password table impractical.
- Two token types (access + refresh) with a `type` claim baked into the
  payload. This is what stops a stolen *refresh* token from being used
  directly as an access token, and vice versa — decode_token() enforces
  the caller checks the type explicitly, so this can't be forgotten.
- Access tokens are short-lived (30 min default); refresh tokens are
  longer-lived (7 days) but can be revoked by the client discarding them.
  Full server-side revocation (a token blocklist) is a real production
  gap noted in the README — deliberately out of scope for a fresher
  portfolio project, but worth being able to name in an interview.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _create_token(subject: str, org_id: str, role: str, token_type: Literal["access", "refresh"], expires_delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,       # user id
        "org_id": org_id,
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(user_id: str, org_id: str, role: str) -> str:
    return _create_token(user_id, org_id, role, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(user_id: str, org_id: str, role: str) -> str:
    return _create_token(user_id, org_id, role, "refresh", timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))


class InvalidTokenError(Exception):
    pass


def decode_token(token: str, expected_type: Literal["access", "refresh"]) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise InvalidTokenError("Token is invalid or expired")

    if payload.get("type") != expected_type:
        raise InvalidTokenError(f"Expected a {expected_type} token, got {payload.get('type')}")

    return payload
