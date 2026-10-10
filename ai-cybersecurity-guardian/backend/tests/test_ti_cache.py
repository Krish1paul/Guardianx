"""Tests for ThreatIntelCache — M4.

Verifies:
- Cache returns None on miss
- Cache returns result on hit
- TTL expiry: entries expire after TTL
- Cache hit sets cached=True (this is done by the service layer, not cache)
- Cache size limit: oldest entry evicted
- TTL=0 disables caching
- Thread safety (basic)
- clear() empties cache
- invalidate() removes single entry
"""

from __future__ import annotations

import os
import threading
import time
from datetime import UTC, datetime

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-at-least-32-chars-long-here")
os.environ.setdefault("ENVIRONMENT", "test")

from app.services.ti_cache import ThreatIntelCache
from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus


def _make_result(status: ThreatIntelStatus = ThreatIntelStatus.CLEAN) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider="mock",
        status=status,
        confidence=0.9,
        reason="test",
        checked_at=datetime.now(UTC),
        provider_error=False,
        cached=False,
    )


class TestCacheBasicOps:
    def test_miss_returns_none(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        assert cache.get("nonexistent") is None

    def test_set_and_get_returns_result(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        result = _make_result()
        cache.set("hash1", result)
        retrieved = cache.get("hash1")
        assert retrieved is not None
        assert retrieved.status == ThreatIntelStatus.CLEAN

    def test_different_hashes_independent(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        r1 = _make_result(ThreatIntelStatus.CLEAN)
        r2 = _make_result(ThreatIntelStatus.MALICIOUS)
        cache.set("hash_a", r1)
        cache.set("hash_b", r2)
        assert cache.get("hash_a").status == ThreatIntelStatus.CLEAN  # type: ignore[union-attr]
        assert cache.get("hash_b").status == ThreatIntelStatus.MALICIOUS  # type: ignore[union-attr]

    def test_invalidate_removes_entry(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        cache.set("hash1", _make_result())
        cache.invalidate("hash1")
        assert cache.get("hash1") is None

    def test_invalidate_nonexistent_no_error(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        cache.invalidate("does_not_exist")  # must not raise

    def test_clear_empties_all(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        for i in range(5):
            cache.set(f"hash_{i}", _make_result())
        cache.clear()
        assert cache.size == 0

    def test_size_property(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        assert cache.size == 0
        cache.set("h1", _make_result())
        assert cache.size == 1

    def test_contains_operator(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        cache.set("h1", _make_result())
        assert "h1" in cache
        assert "h2" not in cache

    def test_len_operator(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60)
        for i in range(3):
            cache.set(f"h{i}", _make_result())
        assert len(cache) == 3


class TestCacheTTL:
    def test_expired_entry_returns_none(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=1)
        cache.set("hash1", _make_result())
        assert cache.get("hash1") is not None
        time.sleep(1.1)
        assert cache.get("hash1") is None

    def test_ttl_zero_disables_cache(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=0)
        cache.set("hash1", _make_result())
        assert cache.get("hash1") is None
        assert cache.size == 0

    def test_entry_survives_within_ttl(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=10)
        cache.set("hash1", _make_result())
        time.sleep(0.05)
        assert cache.get("hash1") is not None


class TestCacheMaxSize:
    def test_oldest_evicted_when_full(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60, max_size=3)
        cache.set("h1", _make_result())
        cache.set("h2", _make_result())
        cache.set("h3", _make_result())
        assert cache.size == 3

        # Adding h4 should evict h1 (oldest)
        cache.set("h4", _make_result())
        assert cache.size == 3
        assert cache.get("h1") is None
        assert cache.get("h4") is not None

    def test_update_existing_key_no_eviction(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60, max_size=2)
        r1 = _make_result(ThreatIntelStatus.CLEAN)
        r2 = _make_result(ThreatIntelStatus.MALICIOUS)
        cache.set("h1", r1)
        cache.set("h1", r2)  # update same key
        assert cache.size == 2 or cache.size == 1  # no eviction beyond 1 key
        # Value should be updated
        result = cache.get("h1")
        assert result is not None
        assert result.status == ThreatIntelStatus.MALICIOUS


class TestCacheThreadSafety:
    def test_concurrent_writes_no_crash(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60, max_size=100)
        errors: list[Exception] = []

        def writer(thread_id: int) -> None:
            try:
                for i in range(20):
                    cache.set(f"hash_{thread_id}_{i}", _make_result())
                    cache.get(f"hash_{thread_id}_{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread safety errors: {errors}"

    def test_concurrent_reads_writes_no_crash(self) -> None:
        cache = ThreatIntelCache(ttl_seconds=60, max_size=50)
        # Pre-populate
        for i in range(10):
            cache.set(f"pre_{i}", _make_result())

        errors: list[Exception] = []

        def reader() -> None:
            try:
                for i in range(50):
                    cache.get(f"pre_{i % 10}")
            except Exception as exc:
                errors.append(exc)

        def writer() -> None:
            try:
                for i in range(50):
                    cache.set(f"new_{i}", _make_result())
            except Exception as exc:
                errors.append(exc)

        threads = [
            *[threading.Thread(target=reader) for _ in range(5)],
            *[threading.Thread(target=writer) for _ in range(5)],
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
