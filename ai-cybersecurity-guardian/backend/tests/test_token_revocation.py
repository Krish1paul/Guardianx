"""Tests for TokenRevocationService — M5 Production Hardening."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.core.redis import InMemoryRedisClient
from app.services.token_revocation import (
    TokenRevocationService,
    get_token_revocation_service,
)


class TestTokenRevocationService:
    def test_revoke_and_check(self) -> None:
        redis_client = InMemoryRedisClient()
        service = TokenRevocationService(redis_client=redis_client)

        jti = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
        assert service.is_token_revoked(jti) is False

        service.revoke_token(jti, ttl_seconds=300)
        assert service.is_token_revoked(jti) is True

        # Different JTI is not revoked
        assert service.is_token_revoked("other-jti-uuid") is False

    def test_empty_jti(self) -> None:
        redis_client = InMemoryRedisClient()
        service = TokenRevocationService(redis_client=redis_client)

        service.revoke_token("", ttl_seconds=300)
        assert service.is_token_revoked("") is False

    def test_ttl_expiry(self) -> None:
        redis_client = InMemoryRedisClient()
        service = TokenRevocationService(redis_client=redis_client)

        jti = "expiring-jti"
        service.revoke_token(jti, ttl_seconds=1)
        assert service.is_token_revoked(jti) is True

        # Manually expire
        key = f"revoked_jti:{jti}"
        redis_client._expires[key] = 0.0
        assert service.is_token_revoked(jti) is False

    def test_redis_error_tolerance(self) -> None:
        mock_redis = MagicMock()
        mock_redis.set.side_effect = Exception("Redis write failed")
        mock_redis.exists.side_effect = Exception("Redis read failed")

        service = TokenRevocationService(redis_client=mock_redis)
        # Does not crash on revoke error
        service.revoke_token("jti-err", ttl_seconds=100)
        # Returns False (safe fallback) on check error
        assert service.is_token_revoked("jti-err") is False

    def test_dependency_factory(self) -> None:
        redis_client = InMemoryRedisClient()
        svc = get_token_revocation_service(redis_client=redis_client)
        assert isinstance(svc, TokenRevocationService)
