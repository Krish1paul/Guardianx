"""Token revocation service — M5 Production Hardening.

Manages access-token JTI revocation using Redis (with in-memory fallback).
Access tokens are stored in the blocklist with a TTL matching their remaining validity.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends

from app.core.redis import RedisClientProtocol, get_redis_client

logger = logging.getLogger(__name__)

_REVOCATION_PREFIX = "revoked_jti:"


class TokenRevocationService:
    """Service to track and verify revoked access token JTIs."""

    def __init__(self, redis_client: RedisClientProtocol | None = None) -> None:
        self._redis = redis_client

    def _get_client(self) -> RedisClientProtocol:
        if self._redis is not None:
            return self._redis
        return get_redis_client()

    def revoke_token(self, jti: str, ttl_seconds: int = 900) -> None:
        """Add a JTI to the revocation list with a time-to-live.

        Args:
            jti:         Unique token identifier (UUID string).
            ttl_seconds: Remaining lifetime of the token in seconds.
        """
        if not jti:
            return
        ttl = max(1, ttl_seconds)
        key = f"{_REVOCATION_PREFIX}{jti}"
        try:
            client = self._get_client()
            client.set(key, "1", ex=ttl)
            logger.info("Revoked access token jti=%s (ttl=%ds)", jti, ttl)
        except Exception as exc:
            logger.error("Failed to revoke token jti=%s in Redis: %s", jti, exc)

    def is_token_revoked(self, jti: str) -> bool:
        """Check if a JTI is in the revocation list.

        Args:
            jti: Unique token identifier.

        Returns:
            ``True`` if revoked; ``False`` if valid or on error (safe fallback).
        """
        if not jti:
            return False
        key = f"{_REVOCATION_PREFIX}{jti}"
        try:
            client = self._get_client()
            return bool(client.exists(key))
        except Exception as exc:
            logger.warning("Failed to check token revocation for jti=%s: %s", jti, exc)
            return False


_revocation_service = TokenRevocationService()


def get_token_revocation_service(
    redis_client: Annotated[RedisClientProtocol, Depends(get_redis_client)],
) -> TokenRevocationService:
    """FastAPI dependency for TokenRevocationService."""
    return TokenRevocationService(redis_client=redis_client)
