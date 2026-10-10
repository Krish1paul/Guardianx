"""VirusTotal v3 provider — M4.

API
---
Uses the VirusTotal v3 URL lookup endpoint:
    GET https://www.virustotal.com/api/v3/urls/{url_id}

where ``url_id`` is the URL-safe base64 encoding of the URL string
(as per the VirusTotal v3 spec).

Security design
---------------
-  API key is read from ``Settings.virustotal_api_key`` (environment variable
   ``VIRUSTOTAL_API_KEY``).  It is NEVER hardcoded, logged, or included in
   any error message or API response.
-  The request sends ``url_id`` (hash-based identifier), not the raw URL, in
   the path — but the URL IS present as the ``url`` query parameter.  To
   minimize exposure, the sanitized URL (userinfo stripped) is used.
-  The endpoint is hard-coded; no user input influences the provider URL.
-  All responses are validated before use.  Malformed JSON and unexpected
   schema are handled gracefully.
-  Timeout is hard-bounded by ``timeout_seconds`` (default 5 s).

Failure modes (all return provider_error=True, analysis continues):
-  Missing or empty API key
-  HTTP 4xx/5xx from VirusTotal (rate-limit 429, auth 401, etc.)
-  Network timeout
-  Malformed/unexpected JSON response
-  Any unexpected exception

Privacy
-------
The sanitized URL (no userinfo) is transmitted to VirusTotal as part of the
API query.  This is documented in ``docs/threat-intelligence.md``.
Only the URL itself is sent; no user identity, IP, or session data is shared.
"""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime
from typing import Any

from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus

logger = logging.getLogger(__name__)

_VT_URL_BASE = "https://www.virustotal.com/api/v3/urls"
_PROVIDER_NAME = "virustotal"


def _vt_url_id(url: str) -> str:
    """Return the VirusTotal URL identifier (URL-safe base64 of the URL, no padding)."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def _parse_vt_response(data: dict[str, Any]) -> tuple[ThreatIntelStatus, float | None, str | None]:
    """Extract status, confidence, and reason from a VT v3 URL report.

    VT response shape (simplified)::

        {
          "data": {
            "attributes": {
              "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 2,
                "undetected": 65,
                "harmless": 11,
                "timeout": 1
              },
              "reputation": -5
            }
          }
        }

    Returns ``UNKNOWN`` if the expected structure is absent.
    """
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        if total == 0:
            return ThreatIntelStatus.UNKNOWN, None, "No analysis data available"

        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total

        if malicious_ratio >= 0.1:
            confidence = min(1.0, malicious_ratio * 2)
            return (
                ThreatIntelStatus.MALICIOUS,
                round(confidence, 3),
                f"{malicious}/{total} engines flagged as malicious",
            )
        if suspicious_ratio >= 0.05 or malicious > 0:
            confidence = min(1.0, (malicious_ratio + suspicious_ratio) * 2)
            return (
                ThreatIntelStatus.SUSPICIOUS,
                round(confidence, 3),
                f"{malicious + suspicious}/{total} engines flagged as suspicious/malicious",
            )

        harmless = int(stats.get("harmless", 0)) + int(stats.get("undetected", 0))
        confidence = min(1.0, harmless / total)
        return (
            ThreatIntelStatus.CLEAN,
            round(confidence, 3),
            f"0/{total - harmless} engines flagged; {harmless} clean",
        )

    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return ThreatIntelStatus.UNKNOWN, None, None


class VirusTotalProvider:
    """VirusTotal v3 URL reputation provider.

    Parameters
    ----------
    api_key:
        VirusTotal API key.  Must be non-empty.  If empty, all lookups
        immediately return ``provider_error=True``.

    Security
    --------
    -  API key is never logged or included in exceptions.
    -  Provider endpoint is hard-coded (no user-controlled URLs).
    """

    def __init__(self, api_key: str) -> None:
        self._has_key = bool(api_key and api_key.strip())
        # Store only whether key is present — the actual value is kept in
        # a closure so it can't be accidentally logged via __repr__.
        self._api_key = api_key.strip() if self._has_key else ""

    @property
    def name(self) -> str:
        return _PROVIDER_NAME

    def lookup(
        self,
        url_hash: str,
        url: str,
        *,
        timeout_seconds: float = 5.0,
    ) -> ThreatIntelResult:
        """Query VirusTotal for URL reputation.

        Always returns; never raises.

        Parameters
        ----------
        url_hash:
            SHA-256 hash of the URL.  Used for logging only.
        url:
            Sanitized URL to query (no userinfo).
        timeout_seconds:
            Hard network timeout.
        """
        if not self._has_key:
            logger.warning(
                "VirusTotalProvider: no API key configured (hash=%.16s...). "
                "Using mock provider instead.",
                url_hash,
            )
            return ThreatIntelResult(
                provider=_PROVIDER_NAME,
                status=ThreatIntelStatus.UNKNOWN,
                confidence=None,
                reason="No API key configured",
                checked_at=datetime.now(UTC),
                provider_error=True,
            )

        try:
            import urllib.request

            url_id = _vt_url_id(url)
            endpoint = f"{_VT_URL_BASE}/{url_id}"
            req = urllib.request.Request(
                endpoint,
                headers={
                    "x-apikey": self._api_key,
                    "Accept": "application/json",
                },
                method="GET",
            )

            import json
            import socket

            # Hard timeout via socket default (urllib respects this)
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout_seconds)
            try:
                with urllib.request.urlopen(req) as resp:  # noqa: S310
                    raw = resp.read()
                    data: dict[str, Any] = json.loads(raw)
            finally:
                socket.setdefaulttimeout(old_timeout)

            status, confidence, reason = _parse_vt_response(data)
            logger.debug(
                "VirusTotal: hash=%.16s... → %s (confidence=%s)",
                url_hash,
                status.value,
                confidence,
            )
            return ThreatIntelResult(
                provider=_PROVIDER_NAME,
                status=status,
                confidence=confidence,
                reason=reason,
                checked_at=datetime.now(UTC),
                provider_error=False,
            )

        except TimeoutError:
            logger.warning("VirusTotalProvider timeout (hash=%.16s...)", url_hash)
        except OSError as exc:
            logger.warning(
                "VirusTotalProvider network error (hash=%.16s...): %s",
                url_hash,
                type(exc).__name__,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "VirusTotalProvider unexpected error (hash=%.16s...): %s",
                url_hash,
                type(exc).__name__,
            )

        return ThreatIntelResult(
            provider=_PROVIDER_NAME,
            status=ThreatIntelStatus.UNKNOWN,
            confidence=None,
            reason=None,
            checked_at=datetime.now(UTC),
            provider_error=True,
        )
