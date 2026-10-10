"""URL feature extraction — M2 / M3 shared module.

This module is **pure and stateless**: it accepts a normalized URL string and
returns a ``URLFeatures`` dataclass.  It performs no I/O, no network requests,
no database access, and has no side effects.

Design intent
-------------
M2 uses these features as input to the deterministic ``URLRiskEngine``.
M3 will use exactly the same features as input to a trained ML model.
No changes to this module should be required for the M3 upgrade.

Security note
-------------
This module does NOT make any network requests to the submitted URL.
It works entirely from the URL string.  DNS resolution, HTTP fetching,
redirect following, and JavaScript execution are all explicitly forbidden
in M2 and beyond.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Suspicious TLD set  (indicative, not exhaustive)
# ---------------------------------------------------------------------------

_SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".club",
        ".work",
        ".click",
        ".link",
        ".online",
        ".site",
        ".live",
        ".ws",
        ".cc",
        ".info",
        ".biz",
        ".mobi",
        ".pw",
        ".icu",
        ".cyou",
    }
)

# ---------------------------------------------------------------------------
# Suspicious lexical terms
# ---------------------------------------------------------------------------

_SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "passwd",
    "reset",
    "banking",
    "wallet",
    "payment",
    "pay",
    "confirm",
    "authentication",
    "authenticate",
    "credential",
    "credentials",
    "recovery",
    "recover",
    "support",
    "helpdesk",
    "webscr",
    "ebayisapi",
)

_CREDENTIAL_KEYWORDS: tuple[str, ...] = (
    "password",
    "passwd",
    "credential",
    "credentials",
    "login",
    "signin",
    "sign-in",
    "authentication",
)

# ---------------------------------------------------------------------------
# IPv4 / IPv6 patterns
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

# Simplified IPv6 detection — covers common forms
_IPV6_RE = re.compile(
    r"^\[?[0-9a-fA-F:]+\]?$"
)


def _is_ipv4(hostname: str) -> bool:
    """Return True if hostname is a valid IPv4 address."""
    m = _IPV4_RE.match(hostname)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _is_ipv6(hostname: str) -> bool:
    """Return True if hostname looks like an IPv6 address."""
    # Strip brackets e.g. [::1]
    h = hostname.strip("[]")
    if ":" not in h:
        return False
    # Must have at least two colons or be a compressed form
    return bool(_IPV6_RE.match(hostname))


# ---------------------------------------------------------------------------
# URLFeatures dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class URLFeatures:
    """Structured feature set extracted from a normalized URL.

    All features are deterministic given the same input URL.
    No network I/O is performed during extraction.

    Attributes
    ----------
    raw_url:
        The normalized URL string that was analyzed.

    --- Structural ---
    url_length:
        Total length of the URL string in characters.
    hostname_length:
        Length of the hostname portion.
    path_length:
        Length of the path portion.
    query_length:
        Length of the query string (excluding the leading ``?``).
    fragment_length:
        Length of the fragment (excluding the leading ``#``).
    num_path_segments:
        Number of non-empty path segments split by ``/``.
    num_query_params:
        Number of ``key=value`` pairs in the query string.
    num_subdomains:
        Number of subdomain labels (host minus registered domain).
    num_dots:
        Total dots in the hostname.
    num_hyphens:
        Total hyphens in the hostname.
    num_underscores:
        Total underscores in the hostname.
    num_digits_in_host:
        Total digit characters in the hostname.
    num_special_chars_in_path:
        Count of non-alphanumeric, non-slash, non-dot characters in path+query.

    --- Host / domain ---
    is_ip_address:
        True if the hostname is a raw IP (v4 or v6).
    is_ipv4:
        True if the hostname is a dotted-decimal IPv4 address.
    is_ipv6:
        True if the hostname is an IPv6 address.
    subdomain_depth:
        Number of subdomain labels (0 for apex domain).
    is_suspicious_tld:
        True if the TLD is in the suspicious TLD set.
    is_punycode:
        True if the hostname contains ``xn--`` (internationalized domain name).
    tld:
        The top-level domain label (e.g. "com", "org").
    registered_domain:
        Best-effort registered domain (e.g. "example.com").

    --- Security ---
    is_https:
        True if scheme is https.
    is_http:
        True if scheme is http.
    has_non_standard_port:
        True if an explicit port is present that differs from the scheme default.
    has_userinfo:
        True if the URL contains a user:password@ component.
    has_encoded_chars:
        True if the URL path/query contains percent-encoded characters.
    double_encoding_indicator:
        True if ``%25`` appears in the URL (encoded percent sign — double-encoding).
    encoding_ratio:
        Fraction of URL characters that are part of percent-encoded sequences.

    --- Lexical ---
    suspicious_keywords_found:
        Tuple of suspicious keyword strings found anywhere in the URL.
    credential_keywords_in_path:
        Tuple of credential-related keywords found in the path+query.
    num_suspicious_keywords:
        Count of distinct suspicious keywords found.
    """

    # Identity
    raw_url: str = field(repr=False)

    # Structural
    url_length: int = 0
    hostname_length: int = 0
    path_length: int = 0
    query_length: int = 0
    fragment_length: int = 0
    num_path_segments: int = 0
    num_query_params: int = 0
    num_subdomains: int = 0
    num_dots: int = 0
    num_hyphens: int = 0
    num_underscores: int = 0
    num_digits_in_host: int = 0
    num_special_chars_in_path: int = 0

    # Host / domain
    is_ip_address: bool = False
    is_ipv4: bool = False
    is_ipv6: bool = False
    subdomain_depth: int = 0
    is_suspicious_tld: bool = False
    is_punycode: bool = False
    tld: str = ""
    registered_domain: str = ""

    # Security
    is_https: bool = False
    is_http: bool = False
    has_non_standard_port: bool = False
    has_userinfo: bool = False
    has_encoded_chars: bool = False
    double_encoding_indicator: bool = False
    encoding_ratio: float = 0.0

    # Lexical
    suspicious_keywords_found: tuple[str, ...] = field(default_factory=tuple)
    credential_keywords_in_path: tuple[str, ...] = field(default_factory=tuple)
    num_suspicious_keywords: int = 0


# ---------------------------------------------------------------------------
# Extraction logic
# ---------------------------------------------------------------------------


def _count_special_chars(text: str) -> int:
    """Count characters that are neither alphanumeric nor ``/`` nor ``.``."""
    return sum(
        1
        for c in text
        if not c.isalnum() and c not in {"/", ".", "=", "&", "-", "_", "~", "%"}
    )


def _compute_encoding_ratio(url: str) -> float:
    """Fraction of URL that is part of percent-encoded sequences.

    Each ``%XX`` triplet counts as 3 characters in the denominator.
    """
    if not url:
        return 0.0
    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", url)) * 3
    return encoded_count / len(url)


def _extract_labels(hostname: str) -> list[str]:
    """Split hostname into DNS labels."""
    return [lbl for lbl in hostname.split(".") if lbl]


def _registered_domain_and_tld(labels: list[str]) -> tuple[str, str]:
    """Best-effort registered domain and TLD extraction.

    This does not use a full Public Suffix List (PSL) — that is a future
    enhancement.  For M2 deterministic rules, two-label approximation is
    sufficient and avoids an external dependency.

    Examples::
        ["accounts", "google", "com"]  → ("google.com", "com")
        ["evil",     "example", "co",  "uk"] → ("example.co.uk", "uk")
    """
    if not labels:
        return ("", "")
    if len(labels) == 1:
        return (labels[0], labels[0])
    # Simple heuristic: if the last two labels look like a country-code + SLD
    # (e.g. co.uk, com.au, co.jp) treat the last three as the registered domain.
    two_label_tld_seconds = {
        "co",
        "com",
        "org",
        "net",
        "gov",
        "edu",
        "ac",
        "ne",
    }
    if len(labels) >= 3 and labels[-2] in two_label_tld_seconds and len(labels[-1]) == 2:
        # country-code TLD with second-level (e.g. co.uk)
        tld = f"{labels[-2]}.{labels[-1]}"
        registered = ".".join(labels[-3:])
    else:
        tld = labels[-1]
        registered = ".".join(labels[-2:])
    return (registered, tld)


def extract(url: str) -> URLFeatures:
    """Extract URL features from a normalized URL string.

    Parameters
    ----------
    url:
        A normalized URL string (see ``app.core.url_utils.normalize_url``).
        Must have a valid scheme (http or https).

    Returns
    -------
    URLFeatures:
        An immutable dataclass containing all extracted features.

    Security guarantee
    ------------------
    This function performs NO network I/O.  It is a pure string parser.
    """
    parsed = urllib.parse.urlparse(url)

    hostname = parsed.hostname or ""
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    port = parsed.port
    userinfo = parsed.username  # None if absent

    # --- Structural ---
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)

    path_segments = [seg for seg in path.split("/") if seg]
    num_path_segments = len(path_segments)

    query_params = urllib.parse.parse_qs(query, keep_blank_values=True)
    num_query_params = len(query_params)

    num_dots = hostname.count(".")
    num_hyphens = hostname.count("-")
    num_underscores = hostname.count("_")
    num_digits_in_host = sum(1 for c in hostname if c.isdigit())

    path_and_query = path + "?" + query if query else path
    num_special_chars_in_path = _count_special_chars(path_and_query)

    # --- Host / domain ---
    ipv4 = _is_ipv4(hostname)
    ipv6 = _is_ipv6(hostname)
    is_ip = ipv4 or ipv6

    labels = _extract_labels(hostname) if not is_ip else []
    num_subdomains = max(0, len(labels) - 2) if not is_ip else 0
    subdomain_depth = num_subdomains

    registered_domain, tld = _registered_domain_and_tld(labels) if not is_ip else ("", "")
    dot_tld = f".{tld}" if tld else ""

    is_suspicious_tld = dot_tld in _SUSPICIOUS_TLDS if not is_ip else False

    # Punycode detection: any label starting with "xn--"
    is_punycode = any(lbl.lower().startswith("xn--") for lbl in labels)

    # --- Security ---
    is_https = scheme == "https"
    is_http = scheme == "http"

    _default_ports = {"http": 80, "https": 443}
    has_non_standard_port = (
        port is not None and port != _default_ports.get(scheme)
    )

    has_userinfo = userinfo is not None

    # Encoding
    full_url_lower = url.lower()
    has_encoded_chars = "%" in path + query
    double_encoding_indicator = "%25" in full_url_lower
    encoding_ratio = _compute_encoding_ratio(path + query)

    # --- Lexical ---
    # Search in lowercased full URL for keyword presence
    url_lower = url.lower()
    path_query_lower = (path + query).lower()

    found_keywords = tuple(
        kw for kw in _SUSPICIOUS_KEYWORDS if kw in url_lower
    )
    cred_in_path = tuple(
        kw for kw in _CREDENTIAL_KEYWORDS if kw in path_query_lower
    )

    return URLFeatures(
        raw_url=url,
        # Structural
        url_length=url_length,
        hostname_length=hostname_length,
        path_length=path_length,
        query_length=query_length,
        fragment_length=fragment_length,
        num_path_segments=num_path_segments,
        num_query_params=num_query_params,
        num_subdomains=num_subdomains,
        num_dots=num_dots,
        num_hyphens=num_hyphens,
        num_underscores=num_underscores,
        num_digits_in_host=num_digits_in_host,
        num_special_chars_in_path=num_special_chars_in_path,
        # Host / domain
        is_ip_address=is_ip,
        is_ipv4=ipv4,
        is_ipv6=ipv6,
        subdomain_depth=subdomain_depth,
        is_suspicious_tld=is_suspicious_tld,
        is_punycode=is_punycode,
        tld=tld,
        registered_domain=registered_domain,
        # Security
        is_https=is_https,
        is_http=is_http,
        has_non_standard_port=has_non_standard_port,
        has_userinfo=has_userinfo,
        has_encoded_chars=has_encoded_chars,
        double_encoding_indicator=double_encoding_indicator,
        encoding_ratio=encoding_ratio,
        # Lexical
        suspicious_keywords_found=found_keywords,
        credential_keywords_in_path=cred_in_path,
        num_suspicious_keywords=len(found_keywords),
    )


# Re-export the SUSPICIOUS_KEYWORDS tuple for use in rule engine / tests
SUSPICIOUS_KEYWORDS = _SUSPICIOUS_KEYWORDS
