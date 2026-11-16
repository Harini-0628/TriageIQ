"""
Shared pytest fixtures.

Design decision: each test gets a fresh in-memory SQLite database
(`sqlite:///:memory:`), created via Base.metadata.create_all() rather than
running Alembic migrations. This is a deliberate, common split: Alembic
migrations are the source of truth for how the REAL database evolves over
time (and are tested separately by actually running `alembic upgrade head`
in CI — see .github/workflows/ci.yml); tests need a fast, fully-isolated
schema per test, and create_all() gives that in milliseconds with zero
file I/O. Using TestClient (ASGI in-process transport) instead of a real
running uvicorn server also eliminates the background-process flakiness
this project hit repeatedly during manual sandbox verification — tests
call straight into the app, no network, no port, no race with a
backgrounded process dying between calls.
"""
import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use")
os.environ["APP_ENV"] = "test"

# get_settings() is lru_cache'd — clear it BEFORE any app module reads
# settings, so every module (including rate_limit.py, imported transitively
# via app.main) sees APP_ENV=test rather than a cached "development" value
# from a previous import in the same interpreter session.
from app.core.config import get_settings
get_settings.cache_clear()

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.db.base_class import Base
from app.db.session import get_db
import app.models  # noqa: F401 — populate Base.metadata with every model
from app.main import app


@pytest.fixture()
def db_session(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # keeps the SAME in-memory DB across connections within one test
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Background tasks (e.g. scan import processing) open their own session
    # via a live lookup of app.db.session.SessionLocal rather than a
    # request-scoped dependency — patching it here is what makes THAT path
    # see the same isolated in-memory database as everything else in the
    # test, instead of silently reconnecting to the real app's DATABASE_URL.
    import app.db.session as db_session_module
    monkeypatch.setattr(db_session_module, "SessionLocal", TestingSessionLocal)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass  # db_session fixture owns closing it, not the request

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def registered_admin(client):
    """Registers a fresh org+admin and returns (access_token, user_email)."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Test Org",
            "email": "admin@testorg.io",
            "password": "SuperSecret123",
            "full_name": "Test Admin",
        },
    )
    assert response.status_code == 201, response.text
    data = response.json()
    return data["access_token"], "admin@testorg.io"


@pytest.fixture()
def auth_headers(registered_admin):
    token, _ = registered_admin
    return {"Authorization": f"Bearer {token}"}
