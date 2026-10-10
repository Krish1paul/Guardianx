"""Tests for User and AuditLog ORM models."""

from __future__ import annotations

import uuid

import pytest
from app.core.security import hash_password
from app.models.audit_log import AuditLog
from app.models.user import User
from sqlalchemy import select
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_user(db: Session, *, email: str = "alice@example.com") -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("S3cur3P@ssw0rd!"),
    )
    db.add(user)
    db.flush()  # assign defaults without committing (keeps rollback isolation)
    return user


def _make_audit_log(
    db: Session,
    *,
    user_id: uuid.UUID | None = None,
    action: str = "test.action",
) -> AuditLog:
    log = AuditLog(
        id=uuid.uuid4(),
        user_id=user_id,
        actor="system",
        action=action,
        resource="/api/v1/test",
        ip_address="127.0.0.1",
    )
    db.add(log)
    db.flush()
    return log


# ---------------------------------------------------------------------------
# User model tests
# ---------------------------------------------------------------------------

class TestUserModel:
    def test_user_can_be_created(self, db: Session) -> None:
        """A User row can be created and queried."""
        user = _make_user(db)
        fetched = db.get(User, user.id)
        assert fetched is not None
        assert fetched.email == "alice@example.com"

    def test_user_has_uuid_primary_key(self, db: Session) -> None:
        """The id column is a UUID, not an integer."""
        user = _make_user(db)
        assert isinstance(user.id, uuid.UUID)

    def test_user_password_hash_is_not_plaintext(self, db: Session) -> None:
        """The stored hash must not equal the plain-text password."""
        user = _make_user(db)
        assert user.password_hash != "S3cur3P@ssw0rd!"

    def test_user_mfa_enabled_defaults_to_false(self, db: Session) -> None:
        """mfa_enabled defaults to False."""
        user = _make_user(db)
        assert user.mfa_enabled is False

    def test_user_last_login_at_defaults_to_none(self, db: Session) -> None:
        """last_login_at is NULL by default."""
        user = _make_user(db)
        assert user.last_login_at is None

    def test_duplicate_email_raises(self, db: Session) -> None:
        """The email UNIQUE constraint prevents duplicate registrations."""
        from sqlalchemy.exc import IntegrityError

        _make_user(db, email="dup@example.com")
        with pytest.raises(IntegrityError):
            _make_user(db, email="dup@example.com")


# ---------------------------------------------------------------------------
# AuditLog model tests
# ---------------------------------------------------------------------------

class TestAuditLogModel:
    def test_audit_log_can_be_created_without_user(self, db: Session) -> None:
        """An AuditLog can exist with user_id = NULL (system event)."""
        log = _make_audit_log(db, user_id=None)
        fetched = db.get(AuditLog, log.id)
        assert fetched is not None
        assert fetched.user_id is None

    def test_audit_log_linked_to_user(self, db: Session) -> None:
        """An AuditLog can reference a User via FK."""
        user = _make_user(db)
        log = _make_audit_log(db, user_id=user.id)

        fetched = db.get(AuditLog, log.id)
        assert fetched is not None
        assert fetched.user_id == user.id

    def test_audit_log_relationship_navigates_to_user(self, db: Session) -> None:
        """AuditLog.user relationship returns the related User object."""
        user = _make_user(db)
        log = _make_audit_log(db, user_id=user.id)

        db.refresh(log)
        assert log.user is not None
        assert log.user.email == "alice@example.com"

    def test_user_audit_logs_relationship(self, db: Session) -> None:
        """User.audit_logs relationship returns all related AuditLog objects."""
        user = _make_user(db)
        _make_audit_log(db, user_id=user.id, action="action.one")
        _make_audit_log(db, user_id=user.id, action="action.two")

        db.refresh(user)
        assert len(user.audit_logs) == 2
        actions = {log.action for log in user.audit_logs}
        assert actions == {"action.one", "action.two"}

    def test_audit_log_has_uuid_primary_key(self, db: Session) -> None:
        """The id column on AuditLog is a UUID."""
        log = _make_audit_log(db)
        assert isinstance(log.id, uuid.UUID)

    def test_audit_logs_query_by_action(self, db: Session) -> None:
        """AuditLogs can be filtered by action (exercises the action index)."""
        user = _make_user(db)
        _make_audit_log(db, user_id=user.id, action="user.login")
        _make_audit_log(db, user_id=user.id, action="url.scan")

        results = db.execute(
            select(AuditLog).where(AuditLog.action == "user.login")
        ).scalars().all()
        assert len(results) == 1
        assert results[0].action == "user.login"
