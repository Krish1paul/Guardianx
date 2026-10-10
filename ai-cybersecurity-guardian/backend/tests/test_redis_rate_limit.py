"""Tests for Redis-backed sliding window rate limiting and fallback — M5."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.core.rate_limit import (
    FallbackRateLimiter,
    InMemoryRateLimiter,
    RedisRateLimiter,
)
from app.core.redis import InMemoryRedisClient


class TestRedisRateLimiter:
    def test_sliding_window_enforcement(self) -> None:
        redis_client = InMemoryRedisClient()
        limiter = RedisRateLimiter(redis_client=redis_client)

        key = "test_ip_1"
        limit = 3
        window = 60.0

        # First 3 requests allowed
        assert limiter.is_allowed(key, limit, window) is True
        assert limiter.is_allowed(key, limit, window) is True
        assert limiter.is_allowed(key, limit, window) is True

        # 4th request rejected
        assert limiter.is_allowed(key, limit, window) is False

        # Different key is independent
        assert limiter.is_allowed("test_ip_2", limit, window) is True

    def test_window_eviction(self) -> None:
        redis_client = InMemoryRedisClient()
        limiter = RedisRateLimiter(redis_client=redis_client)

        key = "test_ip_evict"
        limit = 2
        window = 10.0

        assert limiter.is_allowed(key, limit, window) is True
        assert limiter.is_allowed(key, limit, window) is True
        assert limiter.is_allowed(key, limit, window) is False

        # Shift timestamps into the past
        zset = redis_client._zsets.get(f"ratelimit:{key}", {})
        for m in list(zset.keys()):
            zset[m] -= 20.0

        # Now new requests are allowed
        assert limiter.is_allowed(key, limit, window) is True

    def test_clear(self) -> None:
        redis_client = InMemoryRedisClient()
        limiter = RedisRateLimiter(redis_client=redis_client)

        limiter.is_allowed("k1", 1, 60.0)
        assert limiter.is_allowed("k1", 1, 60.0) is False
        limiter.clear()
        assert limiter.is_allowed("k1", 1, 60.0) is True


class TestFallbackRateLimiter:
    def test_uses_redis_when_healthy(self) -> None:
        redis_client = InMemoryRedisClient()
        redis_limiter = RedisRateLimiter(redis_client=redis_client)
        fallback_limiter = InMemoryRateLimiter()

        limiter = FallbackRateLimiter(
            redis_limiter=redis_limiter,
            fallback_limiter=fallback_limiter,
        )

        assert limiter.is_allowed("ip", 2, 60.0) is True
        assert limiter.is_allowed("ip", 2, 60.0) is True
        assert limiter.is_allowed("ip", 2, 60.0) is False

    def test_falls_back_gracefully_when_redis_fails(self) -> None:
        mock_redis = MagicMock()
        mock_redis.zremrangebyscore.side_effect = Exception("Redis connection timed out")
        redis_limiter = RedisRateLimiter(redis_client=mock_redis)
        fallback_limiter = InMemoryRateLimiter()

        limiter = FallbackRateLimiter(
            redis_limiter=redis_limiter,
            fallback_limiter=fallback_limiter,
        )

        # Redis raises an error, but FallbackRateLimiter intercepts it and uses in-memory limiter
        assert limiter.is_allowed("ip_fail", 2, 60.0) is True
        assert limiter.is_allowed("ip_fail", 2, 60.0) is True
        # In-memory limiter enforces limit
        assert limiter.is_allowed("ip_fail", 2, 60.0) is False

    def test_clear_both(self) -> None:
        redis_client = InMemoryRedisClient()
        redis_limiter = RedisRateLimiter(redis_client=redis_client)
        fallback_limiter = InMemoryRateLimiter()

        limiter = FallbackRateLimiter(
            redis_limiter=redis_limiter,
            fallback_limiter=fallback_limiter,
        )
        limiter.clear()
