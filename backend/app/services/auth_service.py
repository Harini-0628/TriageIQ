"""
Auth business logic.

Design decision: registration creates BOTH an Organization and its first
User (as ADMIN) in a single transaction. This mirrors real B2B SaaS
onboarding (Datadog, Vanta, etc.) — nobody signs up to "no organization,"
they sign up and their company workspace is created for them atomically.
If org creation succeeds but user creation fails, the whole transaction
rolls back — no orphaned organizations.
"""
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token
from app.models.user import User, UserRole
from app.models.organization import Organization
from app.repositories.user_repository import UserRepository, OrganizationRepository
from app.schemas.auth import RegisterRequest, TokenResponse


class AuthError(Exception):
    """Raised for any auth failure the API layer should turn into a 4xx response."""
    pass


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.users = UserRepository(db)
        self.orgs = OrganizationRepository(db)

    def register(self, payload: RegisterRequest) -> TokenResponse:
        if self.users.get_by_email(payload.email) is not None:
            raise AuthError("An account with this email already exists")

        org = self.orgs.create(
            Organization(
                name=payload.organization_name,
                slug=self.orgs.unique_slug_for(payload.organization_name),
            )
        )

        user = self.users.create(
            User(
                org_id=org.id,
                email=payload.email,
                hashed_password=hash_password(payload.password),
                full_name=payload.full_name,
                role=UserRole.ADMIN,  # the person who creates the org is its first admin
            )
        )

        self.db.commit()
        return self._issue_tokens(user)

    def login(self, email: str, password: str) -> TokenResponse:
        user = self.users.get_by_email(email)

        # Deliberately identical error for "no such user" and "wrong password."
        # Distinguishing them lets an attacker enumerate valid emails.
        if user is None or not verify_password(password, user.hashed_password):
            raise AuthError("Incorrect email or password")

        if not user.is_active:
            raise AuthError("This account has been deactivated")

        return self._issue_tokens(user)

    def refresh(self, user: User) -> TokenResponse:
        return self._issue_tokens(user)

    def _issue_tokens(self, user: User) -> TokenResponse:
        return TokenResponse(
            access_token=create_access_token(user.id, user.org_id, user.role.value),
            refresh_token=create_refresh_token(user.id, user.org_id, user.role.value),
        )
