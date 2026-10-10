"""Tests for M5 Security Hardening — Token Revocation, Tracing, Redaction, & Guards."""

from __future__ import annotations

import logging
import uuid

import pytest
from app.core.auth import create_access_token, decode_token
from app.core.config import Settings
from app.core.logging import RedactSensitiveDataFilter, _redact_message, safe_extra
from app.models.user import User
from app.services.token_revocation import TokenRevocationService
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture()
def test_user(db: Session) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"m5user_{uuid.uuid4().hex[:6]}@example.com",
        password_hash="fakehash",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


class TestAccessTokenRevocation:
    def test_revoked_token_rejected_at_me(
        self, client: TestClient, test_user: User
    ) -> None:
        token = create_access_token(test_user.id)
        payload = decode_token(token, expected_type="access")
        jti = str(payload["jti"])

        # 1. Valid token succeeds
        headers = {"Authorization": f"Bearer {token}"}
        res1 = client.get("/api/v1/auth/me", headers=headers)
        assert res1.status_code == 200
        assert res1.json()["id"] == str(test_user.id)

        # 2. Revoke JTI
        revocation_svc = TokenRevocationService()
        revocation_svc.revoke_token(jti, ttl_seconds=900)

        # 3. Subsequent /me request rejected with 401
        res2 = client.get("/api/v1/auth/me", headers=headers)
        assert res2.status_code == 401
        assert "revoked" in res2.json()["detail"].lower()

    def test_revoked_token_rejected_at_analyze_url(
        self, client: TestClient, test_user: User
    ) -> None:
        token = create_access_token(test_user.id)
        payload = decode_token(token, expected_type="access")
        jti = str(payload["jti"])

        headers = {"Authorization": f"Bearer {token}"}
        revocation_svc = TokenRevocationService()
        revocation_svc.revoke_token(jti, ttl_seconds=900)

        res = client.post(
            "/api/v1/analyze/url",
            json={"url": "https://example.com"},
            headers=headers,
        )
        assert res.status_code == 401

    def test_logout_revokes_access_token(
        self, client: TestClient, test_user: User
    ) -> None:
        token = create_access_token(test_user.id)
        headers = {"Authorization": f"Bearer {token}"}
        # Logout with access token in header
        res_logout = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": "dummy.refresh.token"},
            headers=headers,
        )
        assert res_logout.status_code == 204

        # Access token is now revoked
        res_me = client.get("/api/v1/auth/me", headers=headers)
        assert res_me.status_code == 401


class TestCorrelationIdMiddleware:
    def test_echoes_incoming_request_id(self, client: TestClient) -> None:
        custom_id = "test-corr-id-12345"
        res = client.get("/health", headers={"X-Request-ID": custom_id})
        assert res.status_code == 200
        assert res.headers.get("X-Request-ID") == custom_id
        assert res.headers.get("X-Correlation-ID") == custom_id

    def test_generates_request_id_if_absent(self, client: TestClient) -> None:
        res = client.get("/health")
        assert res.status_code == 200
        assert "X-Request-ID" in res.headers
        assert len(res.headers["X-Request-ID"]) > 0


class TestSensitiveLogRedaction:
    def test_query_param_redaction(self) -> None:
        raw = "User requested /api/v1/search?token=secret123&key=myapi456&other=safe"
        redacted = _redact_message(raw)
        assert "secret123" not in redacted
        assert "myapi456" not in redacted
        assert "token=[REDACTED]" in redacted
        assert "key=[REDACTED]" in redacted
        assert "other=safe" in redacted

    def test_bearer_token_redaction(self) -> None:
        raw = "Received header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"
        redacted = _redact_message(raw)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
        assert "Bearer [REDACTED]" in redacted

    def test_sensitive_keys_redaction(self) -> None:
        raw = "Connecting with password=super_secret_db_pass"
        redacted = _redact_message(raw)
        assert "super_secret_db_pass" not in redacted
        assert "[REDACTED]" in redacted

    def test_safe_extra_raises_on_sensitive_key(self) -> None:
        with pytest.raises(ValueError, match="Refusing to log sensitive key"):
            safe_extra(password="secret")

        with pytest.raises(ValueError, match="Refusing to log sensitive key"):
            safe_extra(api_key="123")

        safe_extra(user_id="safe", count=5)

    def test_log_filter_injects_correlation_id(self) -> None:
        filt = RedactSensitiveDataFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        filt.filter(record)
        assert hasattr(record, "correlation_id")


class TestBodySizeLimit:
    def test_oversized_content_length_rejected(self, client: TestClient) -> None:
        headers = {"Content-Length": "2000000"}  # 2MB > default 1MB
        res = client.post(
            "/api/v1/auth/login",
            json={"email": "a@b.com", "password": "x"},
            headers=headers,
        )
        assert res.status_code == 413
        assert "exceeds maximum allowed size" in res.json()["detail"]


class TestProductionConfigGuards:
    def test_dev_mode_skips_validation(self) -> None:
        settings = Settings(environment="development", jwt_secret="")
        # Should not raise in development
        settings.validate_production_secrets()

    def test_prod_rejects_short_jwt_secret(self) -> None:
        settings = Settings(
            environment="production",
            jwt_secret="short",
            database_url="postgresql+psycopg://user:pass@db:5432/prod",
            cors_origins="https://app.example.com",
        )
        with pytest.raises(RuntimeError, match="JWT_SECRET"):
            settings.validate_production_secrets()

    def test_prod_rejects_default_db_url(self) -> None:
        settings = Settings(
            environment="production",
            jwt_secret="a" * 32,
            database_url="postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian",
            cors_origins="https://app.example.com",
        )
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            settings.validate_production_secrets()

    def test_prod_rejects_wildcard_cors(self) -> None:
        settings = Settings(
            environment="production",
            jwt_secret="a" * 32,
            database_url="postgresql+psycopg://user:pass@db:5432/prod",
            cors_origins="*",
        )
        with pytest.raises(RuntimeError, match="CORS_ORIGINS"):
            settings.validate_production_secrets()

    def test_prod_valid_passes(self) -> None:
        settings = Settings(
            environment="production",
            jwt_secret="a" * 32,
            database_url="postgresql+psycopg://user:pass@db:5432/prod",
            cors_origins="https://guardian.example.com",
        )
        settings.validate_production_secrets()
