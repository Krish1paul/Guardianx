"""Security Indicator Normalizer — M8.

Provides deterministic normalization for security indicators:
- URLs (reusing ``app.core.url_utils.normalize_url`` and ``hash_url``)
- Hostnames, subdomains, and registrable domains (pure static parsing, NO DNS/network requests)
- SHA-256 digests (case-insensitive hexadecimal validation)
- Email addresses and sender domains

Security & Privacy Guarantee:
- Performs ZERO network I/O, DNS resolution, or socket calls.
- Pure analytical string transformation pipeline.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.core.url_utils import hash_url, normalize_url

# Common multi-part public suffixes for accurate eTLD+1 derivation
COMMON_TWO_PART_TLDS: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "co.nz",
        "org.nz",
        "co.jp",
        "ne.jp",
        "co.za",
        "com.br",
        "com.mx",
        "com.sg",
        "com.hk",
        "com.tr",
        "co.in",
        "net.in",
        "org.in",
        "gen.in",
        "firm.in",
        "ind.in",
    }
)

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_EMAIL_RE = re.compile(r"^([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$")
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


class IndicatorType(str, Enum):
    """Supported security indicator categories."""

    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    URL_HASH = "URL_HASH"
    MESSAGE_HASH = "MESSAGE_HASH"
    FILE_HASH = "FILE_HASH"
    SENDER_EMAIL = "SENDER_EMAIL"
    SENDER_DOMAIN = "SENDER_DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"


@dataclass(frozen=True)
class NormalizedIndicator:
    """Normalized indicator with type, canonical value, and provenance."""

    type: IndicatorType
    value: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "metadata": self.metadata,
        }


class IndicatorNormalizer:
    """Analytical indicator normalization engine without network I/O."""

    @staticmethod
    def normalize_hash(raw_hash: str) -> str | None:
        """Validate and lowercase a 64-char SHA-256 hex digest."""
        cleaned = raw_hash.strip().lower()
        if _SHA256_RE.match(cleaned):
            return cleaned
        return None

    @staticmethod
    def extract_domain_parts(hostname: str) -> tuple[str, str | None, str | None]:
        """Safely decompose a hostname into (hostname, registered_domain, subdomain).

        No network queries or DNS requests are performed.

        Returns
        -------
        tuple of (canonical_hostname, registered_domain, subdomain)
        """
        host = hostname.strip().lower().rstrip(".")

        # Handle IP addresses
        if _IPV4_RE.match(host):
            return host, None, None

        parts = host.split(".")
        if len(parts) <= 1:
            return host, host, None

        # Check for two-part TLD (e.g. example.co.uk)
        if len(parts) >= 3:
            potential_tld = f"{parts[-2]}.{parts[-1]}"
            if potential_tld in COMMON_TWO_PART_TLDS:
                registered_domain = f"{parts[-3]}.{potential_tld}"
                subdomain = ".".join(parts[:-3]) if len(parts) > 3 else None
                return host, registered_domain, subdomain

        # Standard single TLD (e.g. example.com)
        registered_domain = f"{parts[-2]}.{parts[-1]}"
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else None
        return host, registered_domain, subdomain

    @classmethod
    def extract_url_indicators(cls, raw_url: str) -> list[NormalizedIndicator]:
        """Extract canonical URL hash, hostname, and registered domain indicators."""
        indicators: list[NormalizedIndicator] = []
        try:
            normalized = normalize_url(raw_url)
            digest = hash_url(normalized)
            indicators.append(
                NormalizedIndicator(
                    type=IndicatorType.URL_HASH,
                    value=digest,
                    metadata={"normalized_url": normalized},
                )
            )

            parsed = urllib.parse.urlsplit(normalized)
            hostname = parsed.hostname
            if hostname:
                host, reg_domain, subdomain = cls.extract_domain_parts(hostname)
                if _IPV4_RE.match(host):
                    indicators.append(
                        NormalizedIndicator(
                            type=IndicatorType.IP_ADDRESS,
                            value=host,
                            metadata={},
                        )
                    )
                else:
                    indicators.append(
                        NormalizedIndicator(
                            type=IndicatorType.HOSTNAME,
                            value=host,
                            metadata={"subdomain": subdomain},
                        )
                    )
                    if reg_domain and reg_domain != host:
                        indicators.append(
                            NormalizedIndicator(
                                type=IndicatorType.DOMAIN,
                                value=reg_domain,
                                metadata={},
                            )
                        )
        except Exception:
            pass

        return indicators

    @classmethod
    def extract_sender_indicators(cls, sender: str | None) -> list[NormalizedIndicator]:
        """Extract email and domain indicators from a sender header."""
        if not sender:
            return []

        indicators: list[NormalizedIndicator] = []
        cleaned = sender.strip()

        # Handle 'Name <user@domain.com>' format
        angle_match = re.search(r"<([^>]+)>", cleaned)
        email_candidate = angle_match.group(1).strip() if angle_match else cleaned

        match = _EMAIL_RE.match(email_candidate)
        if match:
            local_part, domain_part = match.group(1).lower(), match.group(2).lower()
            normalized_email = f"{local_part}@{domain_part}"
            indicators.append(
                NormalizedIndicator(
                    type=IndicatorType.SENDER_EMAIL,
                    value=normalized_email,
                    metadata={"local_part": local_part, "domain": domain_part},
                )
            )
            indicators.append(
                NormalizedIndicator(
                    type=IndicatorType.SENDER_DOMAIN,
                    value=domain_part,
                    metadata={},
                )
            )
        else:
            # If plain string or domain
            if "." in cleaned and " " not in cleaned:
                indicators.append(
                    NormalizedIndicator(
                        type=IndicatorType.SENDER_DOMAIN,
                        value=cleaned.lower(),
                        metadata={},
                    )
                )

        return indicators
