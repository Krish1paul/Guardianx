"""In-memory sliding-window rate limiter — M1 Authentication.

⚠️  SINGLE-PROCESS LIMITATION
    This implementation stores request timestamps in a per-process dictionary
    protected by a ``threading.Lock``.  It is NOT suitable for:

    - Multi-worker deployments (e.g. Gunicorn with 4 workers — each worker
      tracks limits independently, effectively multiplying the allowed rate
      by the worker count).
    - Horizontally-scaled deployments running multiple server instances.
    - Production environments that require strict, shared rate enforcement.

    For M5 (Production Hardening), replace ``InMemoryRateLimiter`` with a
    Redis-backed sliding-window implementation.  The public interface
    (``_RateLimiterBase`` / ``get_limiter`` / ``make_rate_limit_dep``) is
    deliberately decoupled from the storage backend so only the backend class
    needs to change — not the route handlers.

Architecture
------------
    ``make_rate_limit_dep(endpoint, limit, window_seconds)``
        Factory that returns a callable class instance.  Class-based
        dependencies avoid PEP 563 (from __future__ import annotations)
        annotation-stringification issues in closures: FastAPI reads the
        __call__ method's parameter annotations via inspect at class definition
        time, when FastAPI and Request are already in scope.

    ``InMemoryRateLimiter``
        Sliding window backed by a per-key ``deque[float]`` of timestamps.
        Expired entries are evicted on each call.

    ``UnlimitedRateLimiter``
        Stub that always allows.  Used in authentication tests to isolate
        rate-limit behaviour into dedicated tests (``test_rate_limit.py``).
"""

# NOTE: from __future__ import annotations is deliberately OMITTED.
# PEP 563 lazy annotation evaluation stringifies all annotations, causing
# FastAPI's dependency injection to fail to resolve framework types like
# Request when they appear inside factory closures or class __call__ methods
# whose globals do not include those names.  Keeping annotations as live
# objects avoids this class of bug entirely.

import logging
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from app.core.config import get_settings
from app.core.redis import RedisClientProtocol, get_redis_client

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Base / interface
# ---------------------------------------------------------------------------


class _RateLimiterBase:
    """Common interface for rate-limit backends."""

    def is_allowed(self, key: str, limit: int, window_seconds: float) -> bool:  # pragma: no cover
        """Return ``True`` if the request is within limits; ``False`` to reject."""
        raise NotImplementedError

    def clear(self) -> None:  # pragma: no cover
        """Reset rate limiter state (useful in tests)."""
        pass


# ---------------------------------------------------------------------------
# In-memory sliding window backend
# ---------------------------------------------------------------------------


class InMemoryRateLimiter(_RateLimiterBase):
    """Sliding-window rate limiter using process-local deques.

    Thread-safe for single-process multi-threaded servers.
    Used for local dev, testing, and as a fallback when Redis is unavailable.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[str, deque[float]] = {}

    def is_allowed(self, key: str, limit: int, window_seconds: float) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            if key not in self._windows:
                self._windows[key] = deque()
            window = self._windows[key]
            # Evict timestamps that have fallen outside the window.
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(now)
            return True

    def clear(self) -> None:
        """Reset all windows.  Useful in tests to start from a clean state."""
        with self._lock:
            self._windows.clear()


# ---------------------------------------------------------------------------
# Redis-backed sliding window backend — M5
# ---------------------------------------------------------------------------


class RedisRateLimiter(_RateLimiterBase):
    """Sliding-window rate limiter backed by Redis sorted sets (ZSET).

    Each request timestamp is stored as a member and score in a ZSET.
    Keys automatically expire after ``window_seconds`` to reclaim memory.
    """

    def __init__(self, redis_client: RedisClientProtocol | None = None) -> None:
        self._redis = redis_client

    def _get_client(self) -> RedisClientProtocol:
        if self._redis is not None:
            return self._redis
        return get_redis_client()

    def is_allowed(self, key: str, limit: int, window_seconds: float) -> bool:
        client = self._get_client()
        redis_key = f"ratelimit:{key}"
        now = time.time()
        cutoff = now - window_seconds

        # Unique member ID per request to support concurrent timestamps
        member = f"{now}:{uuid.uuid4().hex[:8]}"

        # Remove elements older than cutoff
        client.zremrangebyscore(redis_key, "-inf", str(cutoff))
        # Count current requests in window
        count = client.zcard(redis_key)
        if count >= limit:
            return False

        # Add current request and reset TTL
        client.zadd(redis_key, {member: now})
        client.expire(redis_key, int(window_seconds) + 1)
        return True

    def clear(self) -> None:
        """Reset internal store if client supports clear."""
        client = self._get_client()
        if hasattr(client, "clear"):
            client.clear()


# ---------------------------------------------------------------------------
# Fallback rate limiter (Redis with safe InMemory fallback) — M5
# ---------------------------------------------------------------------------


class FallbackRateLimiter(_RateLimiterBase):
    """Tries Redis; on connection failure or error, falls back to in-memory limiter.

    Ensures authentication and other critical endpoints never crash if Redis is down.
    """

    def __init__(
        self,
        redis_limiter: RedisRateLimiter | None = None,
        fallback_limiter: InMemoryRateLimiter | None = None,
    ) -> None:
        self._redis_limiter = redis_limiter or RedisRateLimiter()
        self._fallback_limiter = fallback_limiter or InMemoryRateLimiter()

    def is_allowed(self, key: str, limit: int, window_seconds: float) -> bool:
        try:
            return self._redis_limiter.is_allowed(key, limit, window_seconds)
        except Exception as exc:
            logger.warning(
                "Redis rate limiter failed for key '%s' (%s); falling back to in-memory limiter.",
                key,
                exc,
            )
            return self._fallback_limiter.is_allowed(key, limit, window_seconds)

    def clear(self) -> None:
        self._redis_limiter.clear()
        self._fallback_limiter.clear()


# ---------------------------------------------------------------------------
# Test stub — never rejects
# ---------------------------------------------------------------------------


class UnlimitedRateLimiter(_RateLimiterBase):
    """Stub that always allows.  Injected in tests via dependency_overrides."""

    def is_allowed(self, key: str, limit: int, window_seconds: float) -> bool:
        return True

    def clear(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Module limiter instance & FastAPI accessor
# ---------------------------------------------------------------------------

_in_memory_limiter = InMemoryRateLimiter()
_fallback_limiter = FallbackRateLimiter(
    redis_limiter=RedisRateLimiter(),
    fallback_limiter=_in_memory_limiter,
)


def get_limiter() -> _RateLimiterBase:
    """FastAPI dependency accessor.

    Returns ``FallbackRateLimiter`` (Redis with in-memory fallback) when
    Redis is enabled or configured; otherwise returns ``InMemoryRateLimiter``.

    Override in tests::

        from app.core.rate_limit import get_limiter, UnlimitedRateLimiter
        app.dependency_overrides[get_limiter] = lambda: UnlimitedRateLimiter()
    """
    settings = get_settings()
    if settings.redis_enabled:
        return _fallback_limiter
    return _in_memory_limiter


# ---------------------------------------------------------------------------
# Class-based parameterised dependency (avoids PEP 563 annotation issues)
# ---------------------------------------------------------------------------


class _RateLimitCheck:
    """Callable class that FastAPI uses as a parameterised dependency."""

    def __init__(self, endpoint: str, limit: int, window_seconds: float) -> None:
        self._endpoint = endpoint
        self._limit = limit
        self._window_seconds = window_seconds

    def __call__(
        self,
        request: Request,
        limiter: _RateLimiterBase = Depends(get_limiter),  # noqa: B008
    ) -> None:
        client_ip = request.client.host if request.client else "unknown"
        key = f"{self._endpoint}:{client_ip}"
        if not limiter.is_allowed(key, self._limit, self._window_seconds):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )


def make_rate_limit_dep(
    endpoint: str,
    limit: int,
    window_seconds: float = 60,
) -> Callable[..., None]:
    """Return a FastAPI dependency that enforces a per-IP sliding-window limit."""
    return _RateLimitCheck(endpoint=endpoint, limit=limit, window_seconds=window_seconds)
