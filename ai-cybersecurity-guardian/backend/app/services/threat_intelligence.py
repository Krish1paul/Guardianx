"""Threat Intelligence service abstraction — M4.

Architecture
------------
This module defines:

1.  ``ThreatIntelStatus``   — typed status enum for provider results
2.  ``ThreatIntelResult``   — immutable result dataclass
3.  ``ThreatIntelligenceProvider`` — structural protocol that all providers
    must implement.  Adding a new provider requires only implementing
    ``.lookup()``; no changes to the service are needed.
4.  ``ThreatIntelligenceService`` — orchestrates provider calls, caching,
    and error isolation.

Security design
---------------
-  External results are NEVER the sole decision-maker: they produce an
   additive *signal* that is bounded by ``Settings.threat_intel_max_boost``.
-  Provider errors, timeouts, and malformed responses are all handled
   gracefully; the analysis always continues with the ML baseline.
-  The cache is keyed by ``url_hash`` (SHA-256) — the raw URL is never
   sent to the cache layer and never appears in log output from this module.
-  Provider implementations must NOT log raw URLs at WARNING level or above.

Privacy
-------
-  The normalized URL (minus any userinfo component) is sent to the provider.
  Userinfo (``user:password@host``) is stripped before transmission.
-  Nothing else about the user or session is shared with providers.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from app.services.ti_cache import ThreatIntelCache
from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus

logger = logging.getLogger(__name__)

# Regex that matches the userinfo component ``user:pass@`` in a URL
_USERINFO_RE = re.compile(r"(https?://)([^@]+@)")


def _sanitize_url_for_provider(url: str) -> str:
    """Strip userinfo (user:password@host) from a URL before sending to a provider.

    This ensures credentials embedded in URLs are never transmitted to
    third-party reputation services.

    Examples
    --------
    >>> _sanitize_url_for_provider("https://user:pass@evil.com/login")
    'https://evil.com/login'
    >>> _sanitize_url_for_provider("https://example.com/path")
    'https://example.com/path'
    """
    parsed = urllib.parse.urlparse(url)
    # Replace netloc with hostname-only form (drop user:password)
    safe_netloc = parsed.hostname or parsed.netloc
    if parsed.port:
        safe_netloc = f"{safe_netloc}:{parsed.port}"
    safe = parsed._replace(netloc=safe_netloc)
    return urllib.parse.urlunparse(safe)


# ---------------------------------------------------------------------------
# Provider Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ThreatIntelligenceProvider(Protocol):
    """Structural protocol for threat-intelligence providers.

    All provider implementations must be compatible with this interface.
    Providers must be stateless and thread-safe.

    Security contract
    -----------------
    -  Implementations must NOT log the ``url`` argument at WARNING or above.
    -  Implementations must NOT make network calls with user-controlled URLs.
    -  The provider endpoint must be fixed at construction time from config.
    -  All network calls must respect ``timeout_seconds``.
    """

    @property
    def name(self) -> str:
        """Human-readable provider name (e.g. 'virustotal', 'mock')."""
        ...

    def lookup(
        self,
        url_hash: str,
        url: str,
        *,
        timeout_seconds: float = 5.0,
    ) -> ThreatIntelResult:
        """Query the provider for URL reputation.

        Parameters
        ----------
        url_hash:
            SHA-256 hex digest of the normalized URL.  Used for logging
            (never the raw URL).
        url:
            Sanitized normalized URL to query.  The provider MUST NOT
            transmit this to any third party without prior sanitization.
        timeout_seconds:
            Maximum time to wait for a response.  Implementations must
            honour this and return a ``provider_error=True`` result on
            timeout.

        Returns
        -------
        ThreatIntelResult:
            Never raises; on any error returns a result with
            ``provider_error=True`` and ``status=UNKNOWN``.
        """
        ...


# ---------------------------------------------------------------------------
# ThreatIntelligenceService
# ---------------------------------------------------------------------------


class ThreatIntelligenceService:
    """Orchestrates threat-intelligence enrichment for a single URL scan.

    Usage::

        svc = ThreatIntelligenceService(provider=mock_provider, cache=cache)
        result = svc.enrich(url_hash="abc123...", normalized_url="https://...")

    The service:
    1.  Checks the in-memory cache by ``url_hash``.
    2.  If cache miss, sanitizes the URL (strips userinfo) and calls the provider.
    3.  On any provider error → returns a ``provider_error=True`` result.
    4.  Caches successful (non-error) results.

    This class is stateless across requests and can safely be used as a
    module-level singleton.
    """

    def __init__(
        self,
        provider: ThreatIntelligenceProvider,
        cache: ThreatIntelCache,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._provider = provider
        self._cache = cache
        self._timeout_seconds = timeout_seconds

    def enrich(
        self,
        url_hash: str,
        normalized_url: str,
    ) -> ThreatIntelResult:
        """Return a threat-intelligence result for the given URL.

        Always returns — never raises.

        Parameters
        ----------
        url_hash:
            SHA-256 hex digest of the normalized URL.  Used as cache key.
        normalized_url:
            Normalized URL string.  Userinfo is stripped before any
            provider call.

        Returns
        -------
        ThreatIntelResult:
            Result with ``cached=True`` if served from cache.
        """
        # 1. Cache check (keyed by hash, not raw URL)
        cached = self._cache.get(url_hash)
        if cached is not None:
            logger.debug(
                "TI cache hit: provider=%s hash=%.16s...",
                cached.provider,
                url_hash,
            )
            return ThreatIntelResult(
                provider=cached.provider,
                status=cached.status,
                confidence=cached.confidence,
                reason=cached.reason,
                checked_at=cached.checked_at,
                provider_error=cached.provider_error,
                cached=True,
            )

        # 2. Sanitize URL — strip userinfo before sending to any provider
        safe_url = _sanitize_url_for_provider(normalized_url)

        # 3. Provider call — wrapped so errors never propagate
        try:
            result = self._provider.lookup(
                url_hash=url_hash,
                url=safe_url,
                timeout_seconds=self._timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "TI provider %r raised unexpectedly (hash=%.16s...): %s",
                self._provider.name,
                url_hash,
                type(exc).__name__,
            )
            result = ThreatIntelResult(
                provider=self._provider.name,
                status=ThreatIntelStatus.UNKNOWN,
                confidence=None,
                reason=None,
                checked_at=datetime.now(UTC),
                provider_error=True,
                cached=False,
            )

        # 4. Cache successful (non-error) results only
        if not result.provider_error:
            self._cache.set(url_hash, result)

        return result
