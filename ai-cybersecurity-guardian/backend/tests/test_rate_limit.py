"""Unit tests for the in-memory sliding-window rate limiter.

These tests target InMemoryRateLimiter directly — no FastAPI, no HTTP.
This allows precise control over timing and isolates the limiter from
authentication logic.

Rate-limit behaviour tested:
1. Requests below the limit are allowed.
2. The request that exactly reaches the limit is allowed.
3. Requests above the limit are rejected.
4. After the window expires, the counter resets (requests allowed again).
5. Different keys (different IPs / endpoints) are tracked independently.
6. The UnlimitedRateLimiter stub always allows (test-injection sanity check).

Note: Tests that involve window expiry use ``time.sleep`` with a very short
window (0.1 s) to keep the suite fast.  If the test machine is under heavy
load and a sleep does not advance monotonic time sufficiently, the window
test may flake.  In CI, pin to a low-contention runner.
"""

from __future__ import annotations

import time

from app.core.rate_limit import InMemoryRateLimiter, UnlimitedRateLimiter


class TestInMemoryRateLimiter:
    """Tests for InMemoryRateLimiter."""

    # ------------------------------------------------------------------
    # Below limit
    # ------------------------------------------------------------------

    def test_requests_below_limit_are_allowed(self) -> None:
        """All requests up to (but not reaching) the limit are allowed."""
        limiter = InMemoryRateLimiter()
        limit = 5
        for i in range(limit - 1):
            assert limiter.is_allowed("key", limit, 60), f"Request {i + 1} should be allowed"

    # ------------------------------------------------------------------
    # At limit
    # ------------------------------------------------------------------

    def test_request_at_limit_is_allowed(self) -> None:
        """The request that exactly reaches the limit is still allowed."""
        limiter = InMemoryRateLimiter()
        limit = 3
        for _ in range(limit):
            result = limiter.is_allowed("key", limit, 60)
        # The last call (the 3rd) should be allowed (limit=3 means 3 requests allowed).
        assert result is True

    # ------------------------------------------------------------------
    # Above limit
    # ------------------------------------------------------------------

    def test_request_above_limit_is_rejected(self) -> None:
        """The (limit + 1)th request within the window is rejected."""
        limiter = InMemoryRateLimiter()
        limit = 3
        for _ in range(limit):
            limiter.is_allowed("key", limit, 60)
        # One more — should be rejected.
        assert limiter.is_allowed("key", limit, 60) is False

    def test_multiple_requests_above_limit_all_rejected(self) -> None:
        """All requests after the limit is exceeded are rejected."""
        limiter = InMemoryRateLimiter()
        limit = 2
        for _ in range(limit):
            limiter.is_allowed("key", limit, 60)
        # Three more attempts — all should fail.
        for _ in range(3):
            assert limiter.is_allowed("key", limit, 60) is False

    # ------------------------------------------------------------------
    # Window expiry
    # ------------------------------------------------------------------

    def test_window_expiry_resets_counter(self) -> None:
        """After the window elapses, the counter resets and requests are allowed."""
        limiter = InMemoryRateLimiter()
        limit = 2
        window = 0.1  # 100ms window

        # Saturate the limit.
        for _ in range(limit):
            limiter.is_allowed("key", limit, window)

        # Immediately — should be rejected.
        assert limiter.is_allowed("key", limit, window) is False

        # Wait for the window to expire.
        time.sleep(0.15)

        # After the window — should be allowed again.
        assert limiter.is_allowed("key", limit, window) is True

    def test_partial_window_expiry(self) -> None:
        """Only timestamps outside the window are evicted; recent ones stay."""
        limiter = InMemoryRateLimiter()
        limit = 3
        window = 0.1  # 100ms window

        # First request — within window.
        limiter.is_allowed("key", limit, window)
        # Wait for that timestamp to expire.
        time.sleep(0.15)
        # Two more requests — these are fresh.
        limiter.is_allowed("key", limit, window)
        limiter.is_allowed("key", limit, window)

        # Third fresh request should be allowed (window has 2 fresh + 0 expired).
        assert limiter.is_allowed("key", limit, window) is True

    # ------------------------------------------------------------------
    # Independent keys
    # ------------------------------------------------------------------

    def test_different_keys_are_independent(self) -> None:
        """Requests on separate keys do not affect each other's limits."""
        limiter = InMemoryRateLimiter()
        limit = 2

        # Saturate key A.
        for _ in range(limit):
            limiter.is_allowed("key:a", limit, 60)
        assert limiter.is_allowed("key:a", limit, 60) is False

        # Key B should be unaffected.
        assert limiter.is_allowed("key:b", limit, 60) is True

    def test_endpoint_and_ip_combination_as_key(self) -> None:
        """Simulate the actual key format: endpoint:ip."""
        limiter = InMemoryRateLimiter()
        limit = 1

        limiter.is_allowed("auth:login:1.2.3.4", limit, 60)
        # Same endpoint, same IP — rejected.
        assert limiter.is_allowed("auth:login:1.2.3.4", limit, 60) is False
        # Same endpoint, different IP — allowed.
        assert limiter.is_allowed("auth:login:5.6.7.8", limit, 60) is True

    # ------------------------------------------------------------------
    # clear()
    # ------------------------------------------------------------------

    def test_clear_resets_all_windows(self) -> None:
        """clear() removes all tracked windows so subsequent requests are allowed."""
        limiter = InMemoryRateLimiter()
        limit = 1

        limiter.is_allowed("key", limit, 60)
        assert limiter.is_allowed("key", limit, 60) is False

        limiter.clear()

        assert limiter.is_allowed("key", limit, 60) is True

    # ------------------------------------------------------------------
    # Thread safety (basic smoke test)
    # ------------------------------------------------------------------

    def test_concurrent_requests_do_not_exceed_limit(self) -> None:
        """Multiple threads hammering the same key should respect the limit."""
        import threading

        limiter = InMemoryRateLimiter()
        limit = 10
        allowed: list[bool] = []
        lock = threading.Lock()

        def _request() -> None:
            result = limiter.is_allowed("key", limit, 60)
            with lock:
                allowed.append(result)

        threads = [threading.Thread(target=_request) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for r in allowed if r) == limit
        assert sum(1 for r in allowed if not r) == 10


class TestUnlimitedRateLimiter:
    """Tests for the UnlimitedRateLimiter test stub."""

    def test_always_allows(self) -> None:
        """UnlimitedRateLimiter never rejects, regardless of call count."""
        limiter = UnlimitedRateLimiter()
        for i in range(1000):
            assert limiter.is_allowed("any:key", 1, 60), f"Call {i} should be allowed"

    def test_allows_with_zero_limit(self) -> None:
        """Even with limit=0, the unlimited stub allows."""
        limiter = UnlimitedRateLimiter()
        assert limiter.is_allowed("key", 0, 60) is True
