"""Redis abstraction and client management — M5 Production Hardening.

Provides:
- ``RedisClientProtocol``: Structural protocol for Redis operations.
- ``InMemoryRedisClient``: Thread-safe, expiry-aware in-memory implementation
  used for testing, local development, and graceful fallback when Redis is unreachable.
- ``RedisClient``: Production wrapper around ``redis.Redis`` with timeout protection.
- ``get_redis_client()``: FastAPI dependency / singleton accessor.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from typing import Any, Protocol, runtime_checkable

try:
    import redis
    from redis.exceptions import ConnectionError as RedisConnectionError
    from redis.exceptions import RedisError
    from redis.exceptions import TimeoutError as RedisTimeoutError
except ImportError:  # pragma: no cover
    redis = None  # type: ignore[assignment]
    RedisError = Exception  # type: ignore[misc,assignment]
    RedisConnectionError = Exception  # type: ignore[misc,assignment]
    RedisTimeoutError = Exception  # type: ignore[misc,assignment]

from app.core.config import get_settings

logger = logging.getLogger(__name__)


@runtime_checkable
class RedisClientProtocol(Protocol):
    """Protocol defining the subset of Redis commands used by the application."""

    def ping(self) -> bool:
        """Check if Redis connection is alive."""
        ...

    def get(self, key: str) -> str | None:
        """Get string value by key."""
        ...

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        """Set string value with optional expiration in seconds."""
        ...

    def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        ...

    def exists(self, *keys: str) -> int:
        """Check if one or more keys exist."""
        ...

    def expire(self, key: str, time_sec: int) -> bool:
        """Set key expiration in seconds."""
        ...

    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        """Add members with scores to a sorted set."""
        ...

    def zremrangebyscore(self, key: str, min_score: float | str, max_score: float | str) -> int:
        """Remove members in a sorted set by score range."""
        ...

    def zcard(self, key: str) -> int:
        """Get the number of members in a sorted set."""
        ...

    def close(self) -> None:
        """Close connection pool/client."""
        ...


class InMemoryRedisClient:
    """Thread-safe in-memory Redis implementation for tests and dev/fallback."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._strings: dict[str, str] = {}
        self._expires: dict[str, float] = {}  # key -> monotonic expiry timestamp
        self._zsets: dict[str, dict[str, float]] = {}  # key -> {member: score}

    def _purge_expired(self, key: str, now: float | None = None) -> None:
        """Purge key if expired."""
        if now is None:
            now = time.monotonic()
        if key in self._expires and self._expires[key] <= now:
            self._strings.pop(key, None)
            self._zsets.pop(key, None)
            self._expires.pop(key, None)

    def ping(self) -> bool:
        return True

    def get(self, key: str) -> str | None:
        with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            return self._strings.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            self._strings[key] = str(value)
            self._zsets.pop(key, None)
            if ex is not None:
                self._expires[key] = now + ex
            else:
                self._expires.pop(key, None)
            return True

    def delete(self, *keys: str) -> int:
        deleted = 0
        with self._lock:
            now = time.monotonic()
            for key in keys:
                self._purge_expired(key, now)
                had_str = key in self._strings
                had_zset = key in self._zsets
                self._strings.pop(key, None)
                self._zsets.pop(key, None)
                self._expires.pop(key, None)
                if had_str or had_zset:
                    deleted += 1
        return deleted

    def exists(self, *keys: str) -> int:
        count = 0
        with self._lock:
            now = time.monotonic()
            for key in keys:
                self._purge_expired(key, now)
                if key in self._strings or key in self._zsets:
                    count += 1
        return count

    def expire(self, key: str, time_sec: int) -> bool:
        with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            if key in self._strings or key in self._zsets:
                self._expires[key] = now + time_sec
                return True
            return False

    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        added = 0
        with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            self._strings.pop(key, None)
            if key not in self._zsets:
                self._zsets[key] = {}
            zset = self._zsets[key]
            for member, score in mapping.items():
                if member not in zset:
                    added += 1
                zset[member] = float(score)
        return added

    def zremrangebyscore(self, key: str, min_score: float | str, max_score: float | str) -> int:
        removed = 0
        with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            if key not in self._zsets:
                return 0
            zset = self._zsets[key]

            min_val = float("-inf") if min_score == "-inf" else float(min_score)
            max_val = float("inf") if max_score == "+inf" else float(max_score)

            to_remove = [m for m, s in zset.items() if min_val <= s <= max_val]
            for m in to_remove:
                del zset[m]
                removed += 1
        return removed

    def zcard(self, key: str) -> int:
        with self._lock:
            now = time.monotonic()
            self._purge_expired(key, now)
            if key not in self._zsets:
                return 0
            return len(self._zsets[key])

    def clear(self) -> None:
        """Reset internal store (useful in tests)."""
        with self._lock:
            self._strings.clear()
            self._expires.clear()
            self._zsets.clear()

    def close(self) -> None:
        self.clear()


class RedisClient:
    """Production Redis client wrapper with connection pooling & error tolerance."""

    def __init__(self, url: str, socket_timeout: float = 2.0) -> None:
        if redis is None:  # pragma: no cover
            raise RuntimeError("The 'redis' package is not installed.")
        self._url = url
        self._client: Any = redis.Redis.from_url(
            url,
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_timeout,
            decode_responses=True,
        )

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception as exc:
            logger.warning("Redis ping failed: %s", exc)
            return False

    def get(self, key: str) -> str | None:
        try:
            val = self._client.get(key)
            return str(val) if val is not None else None
        except (RedisError, OSError) as exc:
            logger.warning("Redis get('%s') failed: %s", key, exc)
            raise

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        try:
            return bool(self._client.set(key, value, ex=ex))
        except (RedisError, OSError) as exc:
            logger.warning("Redis set('%s') failed: %s", key, exc)
            raise

    def delete(self, *keys: str) -> int:
        if not keys:
            return 0
        try:
            return int(self._client.delete(*keys))
        except (RedisError, OSError) as exc:
            logger.warning("Redis delete failed: %s", exc)
            raise

    def exists(self, *keys: str) -> int:
        if not keys:
            return 0
        try:
            return int(self._client.exists(*keys))
        except (RedisError, OSError) as exc:
            logger.warning("Redis exists failed: %s", exc)
            raise

    def expire(self, key: str, time_sec: int) -> bool:
        try:
            return bool(self._client.expire(key, time_sec))
        except (RedisError, OSError) as exc:
            logger.warning("Redis expire('%s') failed: %s", key, exc)
            raise

    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        try:
            # redis-py zadd expects mapping of {name: score}
            return int(self._client.zadd(key, mapping))
        except (RedisError, OSError) as exc:
            logger.warning("Redis zadd('%s') failed: %s", key, exc)
            raise

    def zremrangebyscore(self, key: str, min_score: float | str, max_score: float | str) -> int:
        try:
            return int(self._client.zremrangebyscore(key, min_score, max_score))
        except (RedisError, OSError) as exc:
            logger.warning("Redis zremrangebyscore('%s') failed: %s", key, exc)
            raise

    def zcard(self, key: str) -> int:
        try:
            return int(self._client.zcard(key))
        except (RedisError, OSError) as exc:
            logger.warning("Redis zcard('%s') failed: %s", key, exc)
            raise

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._client.close()


_redis_singleton: RedisClientProtocol | None = None
_redis_lock = threading.Lock()


def get_redis_client() -> RedisClientProtocol:
    """Return the configured Redis client singleton or in-memory fallback.

    In production/staging with ``redis_enabled=True`` and a reachable server,
    returns ``RedisClient``. Otherwise, returns ``InMemoryRedisClient``.
    """
    global _redis_singleton
    if _redis_singleton is not None:
        return _redis_singleton

    with _redis_lock:
        if _redis_singleton is not None:
            return _redis_singleton

        settings = get_settings()
        if settings.redis_enabled:
            try:
                client = RedisClient(
                    url=settings.redis_url,
                    socket_timeout=settings.redis_socket_timeout,
                )
                if client.ping():
                    _redis_singleton = client
                    logger.info("Connected to Redis at %s", settings.redis_url.split("@")[-1])
                    return _redis_singleton
                logger.warning("Redis ping failed at startup; falling back to in-memory store.")
            except Exception as exc:
                logger.warning(
                    "Failed to initialize Redis client (%s); falling back to in-memory store.",
                    exc,
                )

        _redis_singleton = InMemoryRedisClient()
        return _redis_singleton


def reset_redis_client(client: RedisClientProtocol | None = None) -> None:
    """Reset the module singleton (useful in tests)."""
    global _redis_singleton
    with _redis_lock:
        if _redis_singleton is not None:
            _redis_singleton.close()
        _redis_singleton = client
