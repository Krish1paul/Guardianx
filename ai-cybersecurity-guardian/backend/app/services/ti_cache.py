"""In-memory TTL cache for Threat Intelligence results — M4.

Design
------
-  Keyed by ``url_hash`` (SHA-256 hex digest) — never by raw URL, so cached
   data does not expose URL content.
-  Thread-safe via a single ``threading.Lock``.
-  Simple TTL eviction: entries expire after ``ttl_seconds``.  Eviction is
   lazy (checked on read) plus a periodic sweep on every 100th write.
-  Maximum size is bounded by ``max_size``; when full the oldest entry is
   evicted (LRU-like: insertion order eviction via ``dict`` ordering in
   Python 3.7+).
-  No Redis, no disk, no subprocess, no network.

Privacy
-------
Cache keys are SHA-256 hashes.  The raw URL and user identity are never
stored in the cache.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from app.services.ti_types import ThreatIntelResult


@dataclass
class _CacheEntry:
    result: ThreatIntelResult
    expires_at: float  # monotonic time


class ThreatIntelCache:
    """Thread-safe in-memory TTL cache for ``ThreatIntelResult`` objects.

    Parameters
    ----------
    ttl_seconds:
        How long (seconds) each entry lives.  Set to 0 to disable caching
        (all lookups miss).
    max_size:
        Maximum number of cached entries.  Oldest entry is dropped when full.
    """

    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._store: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()
        self._write_count = 0
        self._sweep_every = 100  # sweep for expired entries every N writes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, url_hash: str) -> ThreatIntelResult | None:
        """Return a cached result if it exists and has not expired."""
        if self._ttl == 0:
            return None
        with self._lock:
            entry = self._store.get(url_hash)
            if entry is None:
                return None
            if time.monotonic() > entry.expires_at:
                del self._store[url_hash]
                return None
            return entry.result

    def set(self, url_hash: str, result: ThreatIntelResult) -> None:
        """Store a result in the cache."""
        if self._ttl == 0:
            return
        with self._lock:
            # Evict oldest entry if at capacity
            if url_hash not in self._store and len(self._store) >= self._max_size:
                # dict preserves insertion order → first key is oldest
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]

            self._store[url_hash] = _CacheEntry(
                result=result,
                expires_at=time.monotonic() + self._ttl,
            )

            # Periodic sweep for expired entries
            self._write_count += 1
            if self._write_count % self._sweep_every == 0:
                self._sweep()

    def invalidate(self, url_hash: str) -> None:
        """Remove a single entry from the cache."""
        with self._lock:
            self._store.pop(url_hash, None)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        """Current number of entries (including possibly expired ones)."""
        with self._lock:
            return len(self._store)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sweep(self) -> None:
        """Evict all expired entries.  Must be called under self._lock."""
        now = time.monotonic()
        expired = [k for k, v in self._store.items() if now > v.expires_at]
        for k in expired:
            del self._store[k]

    # ------------------------------------------------------------------
    # Allow use as a simple dict-like for testing
    # ------------------------------------------------------------------

    def __contains__(self, url_hash: Any) -> bool:
        return self.get(url_hash) is not None

    def __len__(self) -> int:
        return self.size
