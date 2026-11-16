"""
Auth dependencies — every protected route in every future module depends
on get_current_user (or require_roles) rather than reimplementing token
checking. This is the single choke point for "is this request allowed?" —
exactly what you want to be able to point to in an interview when asked
"how do you enforce authorization consistently across dozens of endpoints?"
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decode_token, InvalidTokenError
from app.db.session import get_db
from app.models.user import User, UserRole
from app.repositories.user_repository import UserRepository

settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token, expected_type="access")
    except InvalidTokenError:
        raise credentials_error

    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_error

    user = UserRepository(db).get_by_id(user_id)
    if user is None or not user.is_active:
        raise credentials_error

    return user


def require_roles(*allowed_roles: UserRole):
    """
    Returns a FastAPI dependency that 403s unless the current user's role
    is in allowed_roles. Used like:
        @router.delete(..., dependencies=[Depends(require_roles(UserRole.ADMIN))])
    """
    def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {[r.value for r in allowed_roles]}",
            )
        return current_user

    return _check
