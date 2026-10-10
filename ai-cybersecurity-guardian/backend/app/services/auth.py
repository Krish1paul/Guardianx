"""Authentication service — M1.

This module contains all authentication business logic.  Route handlers
delegate to ``AuthService`` and translate domain exceptions to HTTP errors.

Security decisions
------------------
- **Email enumeration prevention (login)**: If the email is not found, a dummy
  bcrypt comparison is still performed so that both the "email not found" and
  "wrong password" code paths take roughly the same wall-clock time.
- **Generic login error**: Both "email not found" and "wrong password" raise
  ``InvalidCredentialsError`` — the API surface reveals nothing about whether
  an account exists.
- **Transactional refresh rotation**: The old token is marked ``revoked_at``
  and the new token is inserted in the same database transaction.
  A ``SELECT … FOR UPDATE`` row lock on PostgreSQL prevents two concurrent
  refresh requests from succeeding with the same token.  SQLite (used in
  tests) does not support row-level locking; the behaviour remains correct
  because the test runner is single-threaded.
- **Token reuse = family revocation**: If a consumed token (``revoked_at IS
  NOT NULL``) is presented to ``/auth/refresh``, the entire token family is
  immediately revoked and a ``security.refresh.reuse_detected`` audit event
  is recorded.
- **No raw tokens stored**: Only ``SHA-256(jti)`` is persisted — see
  ``app.core.auth.hash_jti``.

Audit events produced
---------------------
    auth.register.success
    auth.register.duplicate
    auth.login.success
    auth.login.failure
    auth.refresh.success
    auth.refresh.failure
    security.refresh.reuse_detected
    auth.logout
"""

from __future__ import annotations

import functools
import uuid
from datetime import UTC, datetime
from typing import Any

import bcrypt as _bcrypt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import (
    TokenError,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_jti,
)
from app.core.security import hash_password, verify_password
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import TokenPair

# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Base authentication error."""


class InvalidCredentialsError(AuthError):
    """Generic login failure — deliberately does not distinguish wrong email
    from wrong password to prevent account enumeration."""


class EmailAlreadyRegisteredError(AuthError):
    """Registration attempted with an already-registered email."""


class TokenReuseError(AuthError):
    """Refresh token reuse detected.  The token family has been revoked."""


class TokenNotFoundError(AuthError):
    """Refresh token not found in the database."""


# ---------------------------------------------------------------------------
# Timing-safe dummy hash
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """Return a bcrypt hash used for constant-time dummy comparisons.

    Computed once per process lifetime via lru_cache.  Used when an email
    address is not found so that the "not found" and "wrong password" code
    paths take the same wall-clock time, preventing email enumeration via
    timing analysis.
    """
    return _bcrypt.hashpw(b"__timing_sentinel__", _bcrypt.gensalt(rounds=12)).decode()


# ---------------------------------------------------------------------------
# Internal audit helper
# ---------------------------------------------------------------------------


def _audit(
    db: Session,
    *,
    action: str,
    resource: str,
    user_id: uuid.UUID | None = None,
    ip_address: str | None = None,
) -> None:
    """Insert an AuditLog row.

    Does NOT commit — the caller controls transaction boundaries.

    Security: never pass passwords, tokens, or authorization headers as
    values here.  Only user IDs, action names, and resource paths.
    """
    actor = str(user_id) if user_id else "anonymous"
    log = AuditLog(
        id=uuid.uuid4(),
        user_id=user_id,
        actor=actor,
        action=action,
        resource=resource,
        ip_address=ip_address,
    )
    db.add(log)


# ---------------------------------------------------------------------------
# FOR UPDATE dialect helper
# ---------------------------------------------------------------------------


def _apply_for_update(stmt: Any, db: Session) -> Any:
    """Apply ``SELECT … FOR UPDATE`` on PostgreSQL; skip on SQLite.

    SQLite does not support row-level locking.  The behaviour is still correct
    in tests because the test runner is single-threaded.

    On PostgreSQL, this prevents two concurrent requests from successfully
    consuming the same refresh token (the second request will block until the
    first commits, then see ``revoked_at IS NOT NULL`` and trigger reuse
    detection).
    """
    try:
        bind = db.get_bind()
        dialect_name: str = getattr(getattr(bind, "dialect", None), "name", "")
        if dialect_name == "sqlite":
            return stmt
    except Exception:
        pass
    return stmt.with_for_update()


# ---------------------------------------------------------------------------
# AuthService
# ---------------------------------------------------------------------------


class AuthService:
    """Encapsulates all authentication business logic.

    Instantiate with the current database session::

        svc = AuthService(db)
        user = svc.register(email="...", password="...", ip_address="...")
    """

    def __init__(self, db: Session) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        email: str,
        password: str,
        ip_address: str | None = None,
    ) -> User:
        """Register a new user.

        Args:
            email:      Pre-normalised (lowercase, stripped) email address.
            password:   Plaintext password — hashed before storage; never logged.
            ip_address: Client IP for audit log.

        Returns:
            The newly created ``User`` ORM object (without ``password_hash``
            visible in the response schema).

        Raises:
            EmailAlreadyRegisteredError: If the email is already in use.
        """
        existing = self._db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if existing is not None:
            _audit(
                self._db,
                action="auth.register.duplicate",
                resource="/api/v1/auth/register",
                ip_address=ip_address,
            )
            self._db.commit()
            raise EmailAlreadyRegisteredError(email)

        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hash_password(password),
        )
        self._db.add(user)
        self._db.flush()  # populate user.id without committing

        _audit(
            self._db,
            action="auth.register.success",
            resource="/api/v1/auth/register",
            user_id=user.id,
            ip_address=ip_address,
        )
        self._db.commit()
        self._db.refresh(user)
        return user

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def login(
        self,
        email: str,
        password: str,
        ip_address: str | None = None,
    ) -> TokenPair:
        """Authenticate a user and return a token pair.

        Both "email not found" and "wrong password" raise the same
        ``InvalidCredentialsError`` and produce the same response body, so
        that callers cannot determine whether the email exists.

        A timing-safe dummy bcrypt comparison is performed when the user
        is not found to equalise the response time.

        Args:
            email:      Pre-normalised email address.
            password:   Plaintext password — never logged or stored.
            ip_address: Client IP for audit log.

        Returns:
            A ``TokenPair`` containing a fresh access token and refresh token.

        Raises:
            InvalidCredentialsError: Email not found or wrong password.
        """
        user = self._db.execute(select(User).where(User.email == email)).scalar_one_or_none()

        # Always run bcrypt — prevents timing-based email enumeration.
        hash_to_check = user.password_hash if user is not None else _dummy_hash()
        credentials_valid = verify_password(password, hash_to_check)

        if user is None or not credentials_valid:
            _audit(
                self._db,
                action="auth.login.failure",
                resource="/api/v1/auth/login",
                user_id=user.id if user is not None else None,
                ip_address=ip_address,
            )
            self._db.commit()
            raise InvalidCredentialsError()

        # ---- Successful login ----------------------------------------

        user.last_login_at = datetime.now(UTC)

        raw_refresh, jti, expires_at = create_refresh_token(user.id)
        family_id = uuid.uuid4()

        token_record = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=hash_jti(jti),
            family_id=family_id,
            expires_at=expires_at,
        )
        self._db.add(token_record)

        _audit(
            self._db,
            action="auth.login.success",
            resource="/api/v1/auth/login",
            user_id=user.id,
            ip_address=ip_address,
        )
        self._db.commit()

        return TokenPair(
            access_token=create_access_token(user.id),
            refresh_token=raw_refresh,
        )

    # ------------------------------------------------------------------
    # Refresh (transactional rotation)
    # ------------------------------------------------------------------

    def refresh(
        self,
        refresh_token_str: str,
        ip_address: str | None = None,
    ) -> TokenPair:
        """Rotate a refresh token and return a new token pair.

        Transactional rotation (all-or-nothing):
          1. Decode and validate the JWT (type, expiry, claims).
          2. Hash the JTI and locate the stored record (with row lock on PG).
          3. If record is missing → reject.
          4. If record is already revoked → REUSE DETECTED:
               revoke entire family, write security audit event, reject.
          5. If record belongs to a different user → reject.
          6. Mark old token ``revoked_at = now``.
          7. Create new token pair (same ``family_id``).
          8. Persist new refresh token record.
          9. Commit atomically.

        Args:
            refresh_token_str: Raw refresh JWT from the client.
            ip_address:        Client IP for audit log.

        Returns:
            A ``TokenPair`` with a new access token and a new refresh token.

        Raises:
            TokenError:        JWT is expired, malformed, or wrong type.
            TokenNotFoundError: JTI not present in the database.
            TokenReuseError:   Revoked token was re-presented (family revoked).
        """
        # Step 1 — decode + validate JWT
        payload = decode_token(refresh_token_str, expected_type=TokenType.REFRESH)

        try:
            user_id = uuid.UUID(str(payload["sub"]))
            jti = str(payload["jti"])
        except (ValueError, KeyError) as exc:
            raise TokenError(f"Invalid token claims: {exc}") from exc

        token_hash = hash_jti(jti)

        # Step 2 — locate and lock the stored record
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        stmt = _apply_for_update(stmt, self._db)
        token_record = self._db.execute(stmt).scalar_one_or_none()

        # Step 3 — record must exist
        if token_record is None:
            raise TokenNotFoundError("Refresh token not found.")

        # Step 4 — detect reuse (already consumed)
        if token_record.revoked_at is not None:
            self._revoke_family(token_record.family_id)
            _audit(
                self._db,
                action="security.refresh.reuse_detected",
                resource="/api/v1/auth/refresh",
                user_id=user_id,
                ip_address=ip_address,
            )
            self._db.commit()
            raise TokenReuseError("Token reuse detected. All sessions have been revoked.")

        # Step 5 — verify ownership
        if token_record.user_id != user_id:
            raise TokenError("Token user mismatch.")

        # Belt-and-suspenders expiry check (JWT decode already validates exp).
        now = datetime.now(UTC)
        if token_record.expires_at.replace(tzinfo=UTC) <= now:
            raise TokenError("Refresh token has expired.")

        # Step 6 — revoke old token
        token_record.revoked_at = now

        # Step 7 & 8 — create + persist new token (same family)
        raw_new_refresh, new_jti, new_expires_at = create_refresh_token(user_id)
        new_record = RefreshToken(
            id=uuid.uuid4(),
            user_id=user_id,
            token_hash=hash_jti(new_jti),
            family_id=token_record.family_id,
            expires_at=new_expires_at,
        )
        self._db.add(new_record)

        _audit(
            self._db,
            action="auth.refresh.success",
            resource="/api/v1/auth/refresh",
            user_id=user_id,
            ip_address=ip_address,
        )

        # Step 9 — atomic commit
        self._db.commit()

        return TokenPair(
            access_token=create_access_token(user_id),
            refresh_token=raw_new_refresh,
        )

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    def logout(
        self,
        refresh_token_str: str,
        user_id: uuid.UUID,
        ip_address: str | None = None,
    ) -> None:
        """Revoke the provided refresh token.

        Access tokens remain valid until their natural expiry (15 min default).
        This is documented behaviour — access token revocation is deferred to M5
        (Redis-backed blocklist).

        If the refresh token is already invalid or not found, the logout
        still succeeds — user intent is clear.

        Args:
            refresh_token_str: Raw refresh JWT to revoke.
            user_id:           Authenticated user's ID (from access token).
            ip_address:        Client IP for audit log.
        """
        try:
            payload = decode_token(refresh_token_str, expected_type=TokenType.REFRESH)
            jti = str(payload["jti"])
            token_hash = hash_jti(jti)

            token_record = self._db.execute(
                select(RefreshToken).where(
                    RefreshToken.token_hash == token_hash,
                    RefreshToken.user_id == user_id,
                )
            ).scalar_one_or_none()
            if token_record is not None and token_record.revoked_at is None:
                token_record.revoked_at = datetime.now(UTC)

        except TokenError:
            # Token is already invalid — still log the logout attempt.
            pass

        _audit(
            self._db,
            action="auth.logout",
            resource="/api/v1/auth/logout",
            user_id=user_id,
            ip_address=ip_address,
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _revoke_family(self, family_id: uuid.UUID) -> None:
        """Revoke all active tokens belonging to *family_id*.

        Called when token reuse is detected.  Does NOT commit — the caller
        commits after writing the security audit event.
        """
        now = datetime.now(UTC)
        active_tokens = (
            self._db.execute(
                _apply_for_update(
                    select(RefreshToken).where(
                        RefreshToken.family_id == family_id,
                        RefreshToken.revoked_at.is_(None),
                    ),
                    self._db,
                )
            )
            .scalars()
            .all()
        )
        for token in active_tokens:
            token.revoked_at = now
