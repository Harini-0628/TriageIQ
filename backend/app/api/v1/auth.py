"""
Auth routes — thin. All actual logic lives in AuthService; routes only
handle HTTP concerns (status codes, request parsing, dependency wiring).
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.security import decode_token, InvalidTokenError
from app.db.session import get_db
from app.models.user import User, UserRole
from app.repositories.user_repository import UserRepository
from app.schemas.auth import RegisterRequest, TokenResponse, RefreshRequest, UserOut
from app.services.auth_service import AuthService, AuthError
from app.api.v1.deps import get_current_user, require_roles

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")  # registration abuse (mass account creation) is a real threat
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    try:
        return AuthService(db).register(payload)
    except AuthError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")  # tight limit: this is the primary brute-force target
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        # OAuth2PasswordRequestForm names the email field "username" — that's
        # the OAuth2 spec's field name, not a statement about what we store.
        return AuthService(db).login(form_data.username, form_data.password)
    except AuthError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
        token_payload = decode_token(payload.refresh_token, expected_type="refresh")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    user = UserRepository(db).get_by_id(token_payload.get("sub"))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists or is inactive")

    return AuthService(db).refresh(user)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/admin-only", tags=["_demo"])
def admin_only_demo(current_user: User = Depends(require_roles(UserRole.ADMIN))):
    """
    Demo endpoint proving RBAC works end-to-end. Remove once real
    admin-only routes (e.g. user management) exist in later modules.
    """
    return {"message": f"Welcome, admin {current_user.full_name}. This route is admin-only."}
