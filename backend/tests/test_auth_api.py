"""API-level auth tests, using TestClient (in-process ASGI, no real server)."""


def test_register_creates_org_and_returns_tokens(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"organization_name": "Acme", "email": "a@acme.io", "password": "SuperSecret123", "full_name": "A"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data and "refresh_token" in data


def test_register_duplicate_email_rejected(client):
    payload = {"organization_name": "Acme", "email": "dup@acme.io", "password": "SuperSecret123", "full_name": "A"}
    first = client.post("/api/v1/auth/register", json=payload)
    assert first.status_code == 201

    second = client.post("/api/v1/auth/register", json={**payload, "organization_name": "Other Org"})
    assert second.status_code == 400


def test_login_wrong_password_and_nonexistent_user_give_identical_error(client, registered_admin):
    _, email = registered_admin

    wrong_pw = client.post("/api/v1/auth/login", data={"username": email, "password": "WrongPassword1"})
    no_such_user = client.post("/api/v1/auth/login", data={"username": "nobody@nowhere.io", "password": "WrongPassword1"})

    assert wrong_pw.status_code == 401 and no_such_user.status_code == 401
    assert wrong_pw.json()["error"]["message"] == no_such_user.json()["error"]["message"], (
        "Login errors must be identical to prevent email enumeration"
    )


def test_me_requires_valid_token(client, auth_headers):
    authenticated = client.get("/api/v1/auth/me", headers=auth_headers)
    assert authenticated.status_code == 200

    unauthenticated = client.get("/api/v1/auth/me")
    assert unauthenticated.status_code == 401


def test_rbac_denies_analyst_on_admin_only_route(client, registered_admin, db_session):
    """Registers a second org (whose creator is always ADMIN by design),
    downgrades that user to ANALYST directly in the DB, then confirms the
    admin-only route correctly 403s — the exact scenario that surfaced the
    enum-storage bug during manual testing."""
    from app.models.user import User, UserRole

    reg = client.post(
        "/api/v1/auth/register",
        json={"organization_name": "Beta Inc", "email": "analyst@beta.io", "password": "AnotherPass456", "full_name": "B"},
    )
    assert reg.status_code == 201

    user = db_session.query(User).filter(User.email == "analyst@beta.io").first()
    user.role = UserRole.ANALYST
    db_session.commit()

    login = client.post("/api/v1/auth/login", data={"username": "analyst@beta.io", "password": "AnotherPass456"})
    analyst_token = login.json()["access_token"]

    response = client.get("/api/v1/auth/admin-only", headers={"Authorization": f"Bearer {analyst_token}"})
    assert response.status_code == 403
