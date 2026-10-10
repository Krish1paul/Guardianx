"""Mock Threat Intelligence provider — M4.

Purpose
-------
-  Used as the default provider when no external API key is configured.
-  Deterministic: same URL hash → same result.
-  Makes NO network requests (verified by test suite).
-  Safe for use in CI, development, and production when external TI is not
   desired.

Result logic
------------
The mock classifies based on URL features extracted from the provided URL:
-  IPv4 hostname              → MALICIOUS  (confidence 0.90)
-  Suspicious TLD present     → SUSPICIOUS (confidence 0.70)
-  Userinfo present           → SUSPICIOUS (confidence 0.75)
-  Known benign pattern       → CLEAN      (confidence 0.90)
-  Otherwise                  → UNKNOWN    (confidence None)

This gives sensible, predictable results in tests without calling external APIs.
"""

from __future__ import annotations

import ipaddress
import logging
import urllib.parse
from datetime import UTC, datetime

from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus

logger = logging.getLogger(__name__)

# TLDs with historically high phishing rates (mirrors M2 list — never expanded
# here to external sources).
_HIGH_RISK_TLDS = frozenset(
    {
        ".xyz",
        ".top",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".pw",
        ".cc",
        ".ru",
        ".su",
        ".icu",
        ".buzz",
    }
)

_KNOWN_BENIGN_HOSTS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "google.com",
        "github.com",
        "microsoft.com",
        "cloudflare.com",
        "fastly.net",
        "akamaized.net",
    }
)


class MockProvider:
    """Deterministic mock threat-intelligence provider.

    No network calls.  Results are derived purely from URL structure.
    """

    @property
    def name(self) -> str:
        return "mock"

    def lookup(
        self,
        url_hash: str,
        url: str,
        *,
        timeout_seconds: float = 5.0,
    ) -> ThreatIntelResult:
        """Return a deterministic TI result based on URL structure.

        Never raises.  Never makes network calls.
        ``timeout_seconds`` is accepted but unused (no I/O).
        """
        # url_hash is used for logging only — never the raw URL at warning level
        try:
            status, confidence, reason = self._classify(url)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "MockProvider classification failed for hash=%.16s...: %s",
                url_hash,
                type(exc).__name__,
            )
            return ThreatIntelResult(
                provider=self.name,
                status=ThreatIntelStatus.UNKNOWN,
                confidence=None,
                reason=None,
                checked_at=datetime.now(UTC),
                provider_error=True,
            )

        logger.debug(
            "MockProvider: hash=%.16s... → %s (confidence=%s)",
            url_hash,
            status.value,
            confidence,
        )
        return ThreatIntelResult(
            provider=self.name,
            status=status,
            confidence=confidence,
            reason=reason,
            checked_at=datetime.now(UTC),
            provider_error=False,
        )

    # ------------------------------------------------------------------
    # Internal classification logic
    # ------------------------------------------------------------------

    def _classify(self, url: str) -> tuple[ThreatIntelStatus, float | None, str | None]:
        try:
            parsed = urllib.parse.urlparse(url)
        except ValueError:
            return ThreatIntelStatus.UNKNOWN, None, None

        hostname = (parsed.hostname or "").lower()

        # Known benign hosts → CLEAN
        for benign in _KNOWN_BENIGN_HOSTS:
            if hostname == benign or hostname.endswith("." + benign):
                return ThreatIntelStatus.CLEAN, 0.90, "Known reputable domain"

        # IPv4 hostname → MALICIOUS
        if self._is_ipv4(hostname):
            return (
                ThreatIntelStatus.MALICIOUS,
                0.90,
                "IP-based URL — phishing pages frequently use raw IPv4 addresses",
            )

        # Userinfo present → SUSPICIOUS
        if parsed.username:
            return (
                ThreatIntelStatus.SUSPICIOUS,
                0.75,
                "URL contains userinfo (user:pass@host) — credential harvesting pattern",
            )

        # High-risk TLD → SUSPICIOUS
        tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
        if tld in _HIGH_RISK_TLDS:
            return (
                ThreatIntelStatus.SUSPICIOUS,
                0.70,
                f"Domain uses a TLD ({tld}) associated with high phishing rates",
            )

        return ThreatIntelStatus.UNKNOWN, None, None

    @staticmethod
    def _is_ipv4(hostname: str) -> bool:
        try:
            addr = ipaddress.ip_address(hostname)
            return isinstance(addr, ipaddress.IPv4Address)
        except ValueError:
            return False
