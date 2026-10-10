"""URL validation, normalization, and hashing utilities — M2.

This module provides pure utility functions with no I/O, no database access,
and no network requests.

Security design
---------------
- ``validate_url`` rejects disallowed schemes, oversized input, control
  characters, and malformed structure before any parsing occurs.
- ``normalize_url`` produces a canonical form so that equivalent URLs produce
  the same hash.
- ``hash_url`` uses SHA-256 (stable, collision-resistant, not reversible via
  rainbow tables unlike MD5).
- Python's built-in ``hash()`` is intentionally NOT used — it is randomized
  per process and unsuitable for persistent storage.

SSRF safety
-----------
This module performs NO network requests.  It is a string transformation
pipeline only.  Callers must NEVER pass the resulting URL to an HTTP client.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum acceptable URL length in characters.
#: URLs longer than this are rejected before parsing to prevent DoS via
#: pathological inputs in regex or parser.
MAX_URL_LENGTH = 2048

#: Schemes accepted by the analyzer.  All others are rejected.
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

#: Schemes that are explicitly dangerous and always rejected.
BLOCKED_SCHEMES: frozenset[str] = frozenset(
    {
        "file",
        "javascript",
        "data",
        "ftp",
        "ftps",
        "ssh",
        "mailto",
        "tel",
        "blob",
        "about",
        "chrome",
        "chrome-extension",
        "vbscript",
        "ldap",
        "gopher",
        "dict",
        "sftp",
    }
)

# Detect ASCII control characters (0x00–0x1F and 0x7F)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

# Detect whitespace that does not belong in a URL
_WHITESPACE_RE = re.compile(r"\s")


# ---------------------------------------------------------------------------
# Domain exception
# ---------------------------------------------------------------------------


class URLValidationError(ValueError):
    """Raised when a submitted URL fails validation.

    Attributes
    ----------
    detail:
        Human-readable description of the validation failure.
        Safe to surface in API error responses (does not expose internals).
    """

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_url(raw: str) -> None:
    """Validate a raw URL string for acceptability.

    Checks (in order):
    1. Input is a non-empty string.
    2. Does not exceed ``MAX_URL_LENGTH``.
    3. Contains no ASCII control characters.
    4. Contains no raw whitespace characters.
    5. Can be parsed by ``urllib.parse.urlparse``.
    6. Scheme is present and in ``ALLOWED_SCHEMES``.
    7. Hostname is non-empty.
    8. Hostname is not obviously malformed.

    Parameters
    ----------
    raw:
        The raw URL string as submitted by the caller.

    Raises
    ------
    URLValidationError:
        If any validation check fails.  The exception ``detail`` attribute
        contains a safe, human-readable description.
    """
    # 1. Must be a non-empty string (Pydantic should have caught this, but
    #    defend in depth)
    if not raw or not raw.strip():
        raise URLValidationError("URL must not be empty.")

    # 2. Length check (before expensive parsing)
    if len(raw) > MAX_URL_LENGTH:
        raise URLValidationError(
            f"URL exceeds the maximum allowed length of {MAX_URL_LENGTH} characters."
        )

    # 3. Control characters
    if _CONTROL_CHAR_RE.search(raw):
        raise URLValidationError("URL contains invalid control characters.")

    # 4. Whitespace (tabs, newlines, carriage returns, spaces mid-URL)
    stripped = raw.strip()
    # Allow leading/trailing whitespace stripping but not embedded whitespace
    if _WHITESPACE_RE.search(stripped):
        raise URLValidationError("URL contains embedded whitespace characters.")

    # 5. Parse
    try:
        parsed = urllib.parse.urlparse(stripped)
    except Exception as exc:
        raise URLValidationError(f"URL could not be parsed: {exc}") from exc

    # 6. Scheme validation
    scheme = parsed.scheme.lower()
    if not scheme:
        raise URLValidationError(
            "URL is missing a scheme.  Only http:// and https:// URLs are accepted."
        )
    if scheme in BLOCKED_SCHEMES:
        raise URLValidationError(
            f"URL scheme '{scheme}:' is not permitted.  "
            "Only http:// and https:// URLs are accepted."
        )
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(
            f"URL scheme '{scheme}:' is not supported.  "
            "Only http:// and https:// URLs are accepted."
        )

    # 7. Hostname must be present
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError(
            "URL is missing a hostname.  A valid URL must include a domain name or IP address."
        )

    # 8. Hostname sanity — reject obviously malformed hostnames
    # (very long hostnames, null bytes already caught above)
    if len(hostname) > 253:
        raise URLValidationError(
            "URL hostname exceeds the maximum DNS label length of 253 characters."
        )


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_url(raw: str) -> str:
    """Normalize a URL to a canonical form.

    Normalization steps:
    1. Strip leading/trailing whitespace.
    2. Parse the URL.
    3. Lowercase the scheme.
    4. Lowercase the hostname.
    5. Remove default ports (80 for http, 443 for https).
    6. Normalize path: collapse ``//`` sequences; ensure non-empty path is ``/``.
    7. Preserve query string (sorted for canonical key order).
    8. Remove fragment (fragments are client-side and irrelevant to threat analysis).
    9. Rebuild the normalized URL.

    Parameters
    ----------
    raw:
        A URL string that has already passed ``validate_url``.

    Returns
    -------
    str:
        The canonical normalized URL string.

    Notes
    -----
    Two URLs that differ only in hostname casing, default port presence, or
    trailing fragment will produce the same normalized URL and therefore the
    same hash.

    The query string is preserved as-is (not sorted) because changing query
    parameter order could alter the semantics of some URLs.  The normalization
    is conservative: it removes only redundant representation differences, not
    semantic ones.
    """
    url = raw.strip()
    parsed = urllib.parse.urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    # Port: remove if it is the scheme default
    port = parsed.port
    _default_ports = {"http": 80, "https": 443}
    if port == _default_ports.get(scheme):
        port = None

    # Reconstruct netloc (host + optional port, without userinfo for hashing)
    # We preserve userinfo in the normalized URL so the feature extractor can
    # detect it, but lowercase the host portion.
    userinfo = ""
    if parsed.username is not None:
        userinfo = urllib.parse.quote(parsed.username, safe="")
        if parsed.password is not None:
            userinfo += ":" + urllib.parse.quote(parsed.password, safe="")
        userinfo += "@"

    netloc = f"{userinfo}{hostname}:{port}" if port is not None else f"{userinfo}{hostname}"

    # Path normalization
    path = parsed.path
    if not path:
        path = "/"
    # Collapse multiple consecutive slashes (e.g. //foo → /foo)
    while "//" in path:
        path = path.replace("//", "/")

    # Rebuild — preserve query string, drop fragment
    normalized = urllib.parse.urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
    return normalized


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def hash_url(normalized: str) -> str:
    """Compute a stable SHA-256 hex digest of a normalized URL.

    Parameters
    ----------
    normalized:
        The output of ``normalize_url()``.

    Returns
    -------
    str:
        A 64-character lowercase hexadecimal SHA-256 digest.

    Notes
    -----
    - SHA-256 is used (not MD5, not Python's ``hash()``).
    - Python's built-in ``hash()`` is randomized per process and must NOT
      be used for persistent storage.
    - The hash is computed over the UTF-8 encoding of the normalized URL.
    - The same normalized URL always produces the same hash.
    """
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
