"""Comprehensive authentication integration tests — M1.

Test coverage
-------------
Registration:
  - valid registration succeeds (201)
  - invalid email is rejected (422)
  - weak password is rejected (422)
  - duplicate email returns 409
  - email is normalised to lowercase
  - password is not stored as plaintext

Login:
  - valid credentials succeed (200) with token pair
  - incorrect password returns 401
  - non-existent email returns 401 with the same body
  - generic error does not distinguish wrong email from wrong password
  - last_login_at is updated on success
  - audit events are generated on success and failure

JWT:
  - valid access token accepted on /auth/me
  - expired access token rejected (401)
  - malformed token rejected (401)
  - missing Authorization header rejected (401)
  - refresh token used as access token is rejected (401)
  - alg=none token rejected (401)

Protected endpoint /auth/me:
  - unauthenticated request → 401
  - authenticated request → 200 with safe fields
  - password_hash never present in the response

Refresh:
  - valid refresh token → 200 with new token pair
  - rotation issues different tokens
  - old refresh token rejected after rotation
  - revoked refresh token rejected
  - expired refresh token rejected
  - invalid string rejected
  - token-family reuse detection: family revoked; new token also rejected
  - reuse detection creates security audit event

Logout:
  - logout returns 204
  - logout revokes the refresh token
  - logout without access token returns 401
  - logout with invalid refresh token still succeeds (204)
  - logout creates audit event

Rate limiting:
  - 429 returned when limit is exceeded (register, login)
"""

from __future__ import annotations

import base64
import json as _json
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from app.core.auth import TokenType
from app.core.config import get_settings
from app.core.rate_limit import InMemoryRateLimiter, get_limiter
from app.db.session import get_db
from app.main import app
from app.models.audit_log import AuditLog
from app.models.user import User
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EMAIL = "auth_test@example.com"
_PW = "SecurePass1!"
_REGISTER = "/api/v1/auth/register"
_LOGIN = "/api/v1/auth/login"
_REFRESH = "/api/v1/auth/refresh"
_LOGOUT = "/api/v1/auth/logout"
_ME = "/api/v1/auth/me"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register(
    client: TestClient,
    *,
    email: str = _EMAIL,
    password: str = _PW,
) -> dict[str, Any]:
    resp = client.post(_REGISTER, json={"email": email, "password": password})
    assert resp.status_code == 201, resp.text
    return dict(resp.json())


def _login(
    client: TestClient,
    *,
    email: str = _EMAIL,
    password: str = _PW,
) -> dict[str, Any]:
    resp = client.post(_LOGIN, json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_expired_access_token(user_id: uuid.UUID) -> str:
    """Create an access token that expired 2 hours ago."""
    settings = get_settings()
    past = datetime.now(UTC) - timedelta(hours=2)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": TokenType.ACCESS,
        "iat": int(past.timestamp()),
        "exp": int((past + timedelta(minutes=15)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def _make_expired_refresh_token(user_id: uuid.UUID) -> str:
    """Create a refresh token that expired 3 days ago."""
    settings = get_settings()
    past = datetime.now(UTC) - timedelta(days=10)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": TokenType.REFRESH,
        "iat": int(past.timestamp()),
        "exp": int((past + timedelta(days=7)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_valid_registration_succeeds(self, client: TestClient) -> None:
        resp = client.post(
            _REGISTER, json={"email": _EMAIL, "password": _PW}
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == _EMAIL
        assert "id" in body
        assert "created_at" in body

    def test_response_never_contains_password_hash(self, client: TestClient) -> None:
        resp = client.post(_REGISTER, json={"email": _EMAIL, "password": _PW})
        assert "password_hash" not in resp.json()
        assert "password" not in resp.json()

    def test_invalid_email_rejected(self, client: TestClient) -> None:
        resp = client.post(
            _REGISTER, json={"email": "not-an-email", "password": _PW}
        )
        assert resp.status_code == 422

    def test_empty_email_rejected(self, client: TestClient) -> None:
        resp = client.post(_REGISTER, json={"email": "", "password": _PW})
        assert resp.status_code == 422

    def test_weak_password_too_short_rejected(self, client: TestClient) -> None:
        resp = client.post(_REGISTER, json={"email": _EMAIL, "password": "Ab1"})
        assert resp.status_code == 422

    def test_weak_password_no_uppercase_rejected(self, client: TestClient) -> None:
        resp = client.post(
            _REGISTER, json={"email": _EMAIL, "password": "nouppercase1!"}
        )
        assert resp.status_code == 422

    def test_weak_password_no_lowercase_rejected(self, client: TestClient) -> None:
        resp = client.post(
            _REGISTER, json={"email": _EMAIL, "password": "NOLOWERCASE1!"}
        )
        assert resp.status_code == 422

    def test_weak_password_no_digit_rejected(self, client: TestClient) -> None:
        resp = client.post(
            _REGISTER, json={"email": _EMAIL, "password": "NoDigitHere!"}
        )
        assert resp.status_code == 422

    def test_duplicate_email_returns_409(self, client: TestClient) -> None:
        _register(client)
        resp = client.post(_REGISTER, json={"email": _EMAIL, "password": _PW})
        assert resp.status_code == 409

    def test_email_normalised_to_lowercase(
        self, client: TestClient, db: Session
    ) -> None:
        resp = client.post(
            _REGISTER,
            json={"email": "UPPER@EXAMPLE.COM", "password": _PW},
        )
        assert resp.status_code == 201
        user = db.execute(
            select(User).where(User.email == "upper@example.com")
        ).scalar_one_or_none()
        assert user is not None

    def test_email_whitespace_stripped(self, client: TestClient) -> None:
        resp = client.post(
            _REGISTER,
            json={"email": "  trim@example.com  ", "password": _PW},
        )
        assert resp.status_code == 201
        assert resp.json()["email"] == "trim@example.com"

    def test_password_not_stored_plaintext(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        user = db.execute(
            select(User).where(User.email == _EMAIL)
        ).scalar_one()
        assert user.password_hash != _PW
        assert user.password_hash.startswith("$2b$")  # bcrypt

    def test_registration_creates_audit_log(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        log = db.execute(
            select(AuditLog).where(AuditLog.action == "auth.register.success")
        ).scalar_one_or_none()
        assert log is not None
        assert log.user_id is not None


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------


class TestLogin:
    def test_valid_login_returns_token_pair(self, client: TestClient) -> None:
        _register(client)
        resp = client.post(_LOGIN, json={"email": _EMAIL, "password": _PW})
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["token_type"] == "bearer"

    def test_wrong_password_returns_401(self, client: TestClient) -> None:
        _register(client)
        resp = client.post(
            _LOGIN, json={"email": _EMAIL, "password": "WrongPass1!"}
        )
        assert resp.status_code == 401

    def test_nonexistent_email_returns_401(self, client: TestClient) -> None:
        resp = client.post(
            _LOGIN,
            json={"email": "noone@example.com", "password": _PW},
        )
        assert resp.status_code == 401

    def test_wrong_password_and_nonexistent_same_body(
        self, client: TestClient
    ) -> None:
        """Both failure modes must return identical response bodies."""
        _register(client)
        r_wrong = client.post(
            _LOGIN, json={"email": _EMAIL, "password": "WrongPass1!"}
        )
        r_none = client.post(
            _LOGIN,
            json={"email": "nobody@example.com", "password": _PW},
        )
        assert r_wrong.json()["detail"] == r_none.json()["detail"]

    def test_last_login_at_updated_on_success(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        before = datetime.now(UTC)
        _login(client)
        user = db.execute(
            select(User).where(User.email == _EMAIL)
        ).scalar_one()
        assert user.last_login_at is not None
        ts = user.last_login_at.replace(tzinfo=UTC)
        assert ts >= before

    def test_login_success_creates_audit_log(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        _login(client)
        log = db.execute(
            select(AuditLog).where(AuditLog.action == "auth.login.success")
        ).scalar_one_or_none()
        assert log is not None

    def test_login_failure_creates_audit_log(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        client.post(_LOGIN, json={"email": _EMAIL, "password": "WrongPass1!"})
        log = db.execute(
            select(AuditLog).where(AuditLog.action == "auth.login.failure")
        ).scalar_one_or_none()
        assert log is not None

    def test_audit_log_does_not_contain_password(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        _login(client)
        for log in db.execute(select(AuditLog)).scalars().all():
            for field in (log.actor, log.action, log.resource):
                assert _PW not in (field or "")


# ---------------------------------------------------------------------------
# JWT / access-token tests
# ---------------------------------------------------------------------------


class TestJWT:
    def test_valid_access_token_accepted(self, client: TestClient) -> None:
        _register(client)
        tokens = _login(client)
        resp = client.get(_ME, headers=_bearer(tokens["access_token"]))
        assert resp.status_code == 200

    def test_expired_access_token_rejected(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        user = db.execute(
            select(User).where(User.email == _EMAIL)
        ).scalar_one()
        expired = _make_expired_access_token(user.id)
        resp = client.get(_ME, headers=_bearer(expired))
        assert resp.status_code == 401

    def test_malformed_token_rejected(self, client: TestClient) -> None:
        resp = client.get(_ME, headers=_bearer("not.a.jwt"))
        assert resp.status_code == 401

    def test_missing_authorization_header_rejected(
        self, client: TestClient
    ) -> None:
        assert client.get(_ME).status_code == 401

    def test_refresh_token_used_as_access_token_rejected(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        resp = client.get(_ME, headers=_bearer(tokens["refresh_token"]))
        assert resp.status_code == 401

    def test_random_string_as_bearer_rejected(
        self, client: TestClient
    ) -> None:
        resp = client.get(_ME, headers=_bearer("randomgarbage"))
        assert resp.status_code == 401

    def test_alg_none_token_rejected(self, client: TestClient) -> None:
        """alg=none tokens must be rejected."""
        hdr = base64.urlsafe_b64encode(
            b'{"alg":"none","typ":"JWT"}'
        ).rstrip(b"=").decode()
        claims = _json.dumps(
            {
                "sub": str(uuid.uuid4()),
                "type": "access",
                "jti": str(uuid.uuid4()),
                "exp": 9_999_999_999,
            }
        )
        pld = base64.urlsafe_b64encode(claims.encode()).rstrip(b"=").decode()
        none_tok = f"{hdr}.{pld}."
        assert client.get(_ME, headers=_bearer(none_tok)).status_code == 401


# ---------------------------------------------------------------------------
# Protected endpoint /auth/me
# ---------------------------------------------------------------------------


class TestMeEndpoint:
    def test_unauthenticated_returns_401(self, client: TestClient) -> None:
        assert client.get(_ME).status_code == 401

    def test_authenticated_returns_200(self, client: TestClient) -> None:
        _register(client)
        tokens = _login(client)
        resp = client.get(_ME, headers=_bearer(tokens["access_token"]))
        assert resp.status_code == 200

    def test_response_contains_expected_fields(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        body = client.get(
            _ME, headers=_bearer(tokens["access_token"])
        ).json()
        assert "id" in body
        assert "email" in body
        assert "created_at" in body
        assert "mfa_enabled" in body

    def test_response_never_contains_password_hash(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        body = client.get(
            _ME, headers=_bearer(tokens["access_token"])
        ).json()
        assert "password_hash" not in body
        assert "password" not in body
        assert "refresh_token" not in body

    def test_response_email_matches_registered(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        body = client.get(
            _ME, headers=_bearer(tokens["access_token"])
        ).json()
        assert body["email"] == _EMAIL


# ---------------------------------------------------------------------------
# Refresh token rotation tests
# ---------------------------------------------------------------------------


class TestRefreshRotation:
    def test_valid_refresh_returns_new_token_pair(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        resp = client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        )
        assert resp.status_code == 200
        new = resp.json()
        assert "access_token" in new
        assert "refresh_token" in new

    def test_rotation_issues_different_tokens(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        new = client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        ).json()
        assert new["access_token"] != tokens["access_token"]
        assert new["refresh_token"] != tokens["refresh_token"]

    def test_old_refresh_token_rejected_after_rotation(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        )
        resp = client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        )
        assert resp.status_code == 401

    def test_revoked_refresh_token_rejected(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        client.post(
            _LOGOUT,
            json={"refresh_token": tokens["refresh_token"]},
            headers=_bearer(tokens["access_token"]),
        )
        resp = client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        )
        assert resp.status_code == 401

    def test_expired_refresh_token_rejected(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        user = db.execute(
            select(User).where(User.email == _EMAIL)
        ).scalar_one()
        expired = _make_expired_refresh_token(user.id)
        resp = client.post(_REFRESH, json={"refresh_token": expired})
        assert resp.status_code == 401

    def test_completely_invalid_refresh_token_rejected(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            _REFRESH, json={"refresh_token": "garbage.token.value"}
        )
        assert resp.status_code == 401

    def test_token_reuse_revokes_entire_family(
        self, client: TestClient
    ) -> None:
        """Reusing a consumed token revokes the whole family."""
        _register(client)
        tokens = _login(client)
        old_refresh = tokens["refresh_token"]

        # Consume the token — returns new pair.
        r2 = client.post(_REFRESH, json={"refresh_token": old_refresh})
        assert r2.status_code == 200
        new_tokens = r2.json()

        # Reuse old (consumed) token — triggers family revocation.
        r3 = client.post(_REFRESH, json={"refresh_token": old_refresh})
        assert r3.status_code == 401

        # New token from the same family must also be rejected now.
        r4 = client.post(
            _REFRESH,
            json={"refresh_token": new_tokens["refresh_token"]},
        )
        assert r4.status_code == 401

    def test_reuse_detection_creates_security_audit_event(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        tokens = _login(client)
        old_refresh = tokens["refresh_token"]
        client.post(_REFRESH, json={"refresh_token": old_refresh})
        client.post(_REFRESH, json={"refresh_token": old_refresh})  # reuse
        log = db.execute(
            select(AuditLog).where(
                AuditLog.action == "security.refresh.reuse_detected"
            )
        ).scalar_one_or_none()
        assert log is not None

    def test_refresh_success_creates_audit_event(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        tokens = _login(client)
        client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        )
        log = db.execute(
            select(AuditLog).where(AuditLog.action == "auth.refresh.success")
        ).scalar_one_or_none()
        assert log is not None

    def test_new_token_from_rotation_works_on_me(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        new_tokens = client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        ).json()
        resp = client.get(
            _ME, headers=_bearer(new_tokens["access_token"])
        )
        assert resp.status_code == 200

    def test_access_token_used_as_refresh_rejected(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        resp = client.post(
            _REFRESH, json={"refresh_token": tokens["access_token"]}
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Logout tests
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_returns_204(self, client: TestClient) -> None:
        _register(client)
        tokens = _login(client)
        resp = client.post(
            _LOGOUT,
            json={"refresh_token": tokens["refresh_token"]},
            headers=_bearer(tokens["access_token"]),
        )
        assert resp.status_code == 204

    def test_logout_revokes_refresh_token(self, client: TestClient) -> None:
        _register(client)
        tokens = _login(client)
        client.post(
            _LOGOUT,
            json={"refresh_token": tokens["refresh_token"]},
            headers=_bearer(tokens["access_token"]),
        )
        resp = client.post(
            _REFRESH, json={"refresh_token": tokens["refresh_token"]}
        )
        assert resp.status_code == 401

    def test_logout_without_access_token_returns_401(
        self, client: TestClient
    ) -> None:
        _register(client)
        tokens = _login(client)
        resp = client.post(
            _LOGOUT, json={"refresh_token": tokens["refresh_token"]}
        )
        assert resp.status_code == 401

    def test_logout_with_invalid_refresh_still_succeeds(
        self, client: TestClient
    ) -> None:
        """Grace logout — user intent is clear even if token is invalid."""
        _register(client)
        tokens = _login(client)
        resp = client.post(
            _LOGOUT,
            json={"refresh_token": "invalid.token.value"},
            headers=_bearer(tokens["access_token"]),
        )
        assert resp.status_code == 204

    def test_logout_creates_audit_event(
        self, client: TestClient, db: Session
    ) -> None:
        _register(client)
        tokens = _login(client)
        client.post(
            _LOGOUT,
            json={"refresh_token": tokens["refresh_token"]},
            headers=_bearer(tokens["access_token"]),
        )
        log = db.execute(
            select(AuditLog).where(AuditLog.action == "auth.logout")
        ).scalar_one_or_none()
        assert log is not None


# ---------------------------------------------------------------------------
# Rate limiting (endpoint-level)
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Verify 429 is returned when the rate limit is exceeded.

    Uses a real InMemoryRateLimiter (not the unlimited stub) to confirm
    endpoint-level integration works.
    """

    @pytest.fixture()
    def limited_client(
        self, db: Session
    ) -> Generator[TestClient, None, None]:
        """TestClient with real rate limiter injected."""

        def _override_db() -> Generator[Session, None, None]:
            yield db

        real_limiter = InMemoryRateLimiter()

        def _override_limiter() -> InMemoryRateLimiter:
            return real_limiter

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_limiter] = _override_limiter
        with TestClient(app) as c:
            yield c
        app.dependency_overrides.clear()

    def test_register_rate_limit_enforced(
        self, limited_client: TestClient
    ) -> None:
        settings = get_settings()
        limit = settings.rate_limit_register
        for i in range(limit):
            limited_client.post(
                _REGISTER,
                json={"email": f"u{i}@x.com", "password": _PW},
            )
        resp = limited_client.post(
            _REGISTER, json={"email": "over@x.com", "password": _PW}
        )
        assert resp.status_code == 429

    def test_login_rate_limit_enforced(
        self, limited_client: TestClient
    ) -> None:
        settings = get_settings()
        limit = settings.rate_limit_login
        for _ in range(limit):
            limited_client.post(
                _LOGIN, json={"email": "u@x.com", "password": _PW}
            )
        resp = limited_client.post(
            _LOGIN, json={"email": "u@x.com", "password": _PW}
        )
        assert resp.status_code == 429
