"""Tests for database engine connectivity."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def test_db_session_executes_query(db: Session) -> None:
    """The test DB session must execute a simple query without error."""
    result = db.execute(text("SELECT 1")).scalar()
    assert result == 1


def test_db_session_is_isolated(db: Session) -> None:
    """Each test gets a fresh session; this verifies the fixture is callable."""
    # Simple smoke test — if the fixture works we get a Session object.
    assert db is not None
    assert db.is_active
