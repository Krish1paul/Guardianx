"""Shared types for the Threat Intelligence subsystem — M4.

Kept in a separate module to avoid circular imports between
``threat_intelligence``, ``ti_cache``, and the providers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class ThreatIntelStatus(str, Enum):
    """Reputation status returned by a threat-intelligence provider."""

    CLEAN = "CLEAN"  # provider found URL and rated it clean
    SUSPICIOUS = "SUSPICIOUS"  # flagged as suspicious
    MALICIOUS = "MALICIOUS"  # flagged as definitively malicious
    UNKNOWN = "UNKNOWN"  # provider had no data, or call failed


@dataclass(frozen=True)
class ThreatIntelResult:
    """Immutable result from a threat-intelligence provider lookup.

    Fields
    ------
    provider:
        Short name of the provider (e.g. ``"virustotal"``, ``"mock"``).
    status:
        Reputation verdict.
    confidence:
        Normalised confidence [0.0, 1.0], or None if not reported.
    reason:
        Human-readable provider reason, or None.
    checked_at:
        UTC timestamp when the lookup was performed (or when the cached
        result was originally fetched).
    provider_error:
        True when the provider call failed (timeout, network error, invalid
        response, missing API key, etc.).  In this case ``status`` is
        always ``UNKNOWN`` and the result must not influence scoring.
    cached:
        True when this result was served from the in-memory cache.
    """

    provider: str
    status: ThreatIntelStatus
    confidence: float | None
    reason: str | None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    provider_error: bool = False
    cached: bool = False
