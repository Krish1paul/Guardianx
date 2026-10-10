"""Shared pytest fixtures.

Test isolation strategy
-----------------------
- All tests use an **in-memory SQLite** database created once per session.
- Each test gets its own connection + savepoint; the outer transaction is
  rolled back after every test so no state bleeds between tests.
- The FastAPI ``TestClient`` overrides ``get_db`` (database) and
  ``get_limiter`` (rate limiter) via ``dependency_overrides`` so:
    - Tests run against the same in-memory SQLite session.
    - Rate limits are disabled — auth logic is tested separately from
      rate-limit logic (which has its own ``test_rate_limit.py``).

SQLite vs PostgreSQL differences
---------------------------------
- ``UUID(as_uuid=True)`` → ``CHAR(32)`` on SQLite — UUIDs still work.
- ``DateTime(timezone=True)`` → naive UTC datetime on SQLite.
- ``SELECT … FOR UPDATE`` is skipped on SQLite (not supported);
  the service layer detects this via dialect inspection.
- FK constraints require ``PRAGMA foreign_keys=ON``.

To run against a real PostgreSQL instance, set:
    TEST_DATABASE_URL=postgresql+psycopg://user:pass@host/testdb
"""

from __future__ import annotations

# ============================================================
# Set test environment variables BEFORE any app imports.
# get_settings() is cached via lru_cache; these must be in
# place the first time it is called.
# ============================================================
import os

os.environ.setdefault(
    "JWT_SECRET",
    "test-jwt-secret-at-least-32-characters-long-for-testing",
)
os.environ.setdefault("ENVIRONMENT", "test")
# ============================================================

from collections.abc import Generator
from typing import Any

import pytest
from app.core.rate_limit import UnlimitedRateLimiter, get_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# Database engine
# ---------------------------------------------------------------------------
_TEST_DB_URL = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")

_connect_args: dict[str, object] = {}
if _TEST_DB_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

_test_engine = create_engine(
    _TEST_DB_URL,
    connect_args=_connect_args,
    future=True,
)

# Enable FK enforcement for SQLite (off by default).
if _TEST_DB_URL.startswith("sqlite"):

    @event.listens_for(_test_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn: Any, _: object) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


_TestSessionLocal = sessionmaker(
    bind=_test_engine, autoflush=False, autocommit=False, future=True
)

# ---------------------------------------------------------------------------
# Session-scoped table creation
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def _create_tables() -> Generator[None, None, None]:
    import app.models  # noqa: F401 — registers all ORM models with Base.metadata

    Base.metadata.create_all(bind=_test_engine)
    yield
    Base.metadata.drop_all(bind=_test_engine)


# ---------------------------------------------------------------------------
# Per-test DB session with rollback isolation
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    """Provide a DB session that rolls back after every test."""
    connection = _test_engine.connect()
    transaction = connection.begin()
    session = _TestSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


# ---------------------------------------------------------------------------
# FastAPI test client
# Overrides: get_db (test session) + get_limiter (unlimited — no rate limits)
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(db: Session) -> Generator[TestClient, None, None]:
    """Provide a TestClient with DB and rate-limit overrides."""

    def _override_get_db() -> Generator[Session, None, None]:
        yield db

    def _override_get_limiter() -> UnlimitedRateLimiter:
        return UnlimitedRateLimiter()

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_limiter] = _override_get_limiter
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
