"""
Database engine + session management.

Design decision: we use SQLAlchemy's sessionmaker with a request-scoped
session via FastAPI's dependency injection (get_db). This guarantees each
HTTP request gets its own isolated session that is always closed —
including on exceptions — which prevents connection leaks under load.
"""
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import get_settings

settings = get_settings()

# connect_args is SQLite-specific: it allows the connection to be used
# across the single-threaded dev server. Ignored entirely for Postgres.
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,  # avoids "server closed the connection unexpectedly" after idle periods
    future=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
