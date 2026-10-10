"""Tests for URL validation and normalization — M2.

Tests cover:
- Valid URLs (accepted)
- Invalid URLs (rejected with appropriate errors)
- Normalization behavior
- Hash consistency
"""

from __future__ import annotations

import hashlib

import pytest
from app.core.url_utils import (
    URLValidationError,
    hash_url,
    normalize_url,
    validate_url,
)

# ---------------------------------------------------------------------------
# Validation — valid URLs
# ---------------------------------------------------------------------------


class TestValidateAccepted:
    """These URLs should pass validation without raising."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/",
            "https://example.com/login",
            "http://example.com/",
            "https://sub.example.com/path?q=1",
            "https://example.com:8443/secure",
            "https://192.168.1.1/admin",
            "https://[::1]/",
            "https://user:pass@example.com/",
            "https://xn--n3h.example.com/",  # punycode
        ],
    )
    def test_valid_url_accepted(self, url: str) -> None:
        # Should not raise
        validate_url(url)


# ---------------------------------------------------------------------------
# Validation — invalid URLs (rejected)
# ---------------------------------------------------------------------------


class TestValidateRejected:
    def test_empty_string(self) -> None:
        with pytest.raises(URLValidationError, match="empty"):
            validate_url("")

    def test_whitespace_only(self) -> None:
        with pytest.raises(URLValidationError, match="empty"):
            validate_url("   ")

    def test_missing_scheme(self) -> None:
        with pytest.raises(URLValidationError, match="scheme"):
            validate_url("example.com/login")

    def test_unsupported_scheme_ftp(self) -> None:
        with pytest.raises(URLValidationError, match="scheme"):
            validate_url("ftp://example.com/file.txt")

    def test_unsupported_scheme_file(self) -> None:
        with pytest.raises(URLValidationError, match="scheme"):
            validate_url("file:///etc/passwd")

    def test_unsupported_scheme_javascript(self) -> None:
        with pytest.raises(URLValidationError, match="scheme"):
            validate_url("javascript:alert(1)")

    def test_unsupported_scheme_data(self) -> None:
        with pytest.raises(URLValidationError, match="scheme"):
            validate_url("data:text/html,<h1>hello</h1>")

    def test_unsupported_scheme_mailto(self) -> None:
        with pytest.raises(URLValidationError, match="scheme"):
            validate_url("mailto:user@example.com")

    def test_unsupported_scheme_ssh(self) -> None:
        with pytest.raises(URLValidationError, match="scheme"):
            validate_url("ssh://root@server.com")

    def test_missing_hostname(self) -> None:
        with pytest.raises(URLValidationError, match="hostname"):
            validate_url("https:///path")

    def test_oversized_url(self) -> None:
        long_url = "https://example.com/" + "a" * 3000
        with pytest.raises(URLValidationError, match="length"):
            validate_url(long_url)

    def test_control_character_null(self) -> None:
        with pytest.raises(URLValidationError, match="control"):
            validate_url("https://example.com/\x00path")

    def test_control_character_newline(self) -> None:
        with pytest.raises(URLValidationError, match="control"):
            validate_url("https://example.com/pa\nth")

    def test_control_character_tab(self) -> None:
        with pytest.raises(URLValidationError, match="control"):
            validate_url("https://example.com/pa\th")

    def test_embedded_whitespace(self) -> None:
        with pytest.raises(URLValidationError, match="whitespace"):
            validate_url("https://example .com/path")

    def test_leading_whitespace_stripped(self) -> None:
        # Leading/trailing whitespace is acceptable (stripped before check)
        validate_url("  https://example.com/  ")

    def test_hostname_too_long(self) -> None:
        long_host = "a" * 254
        with pytest.raises(URLValidationError):
            validate_url(f"https://{long_host}/")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_lowercase_hostname(self) -> None:
        assert "example.com" in normalize_url("https://EXAMPLE.COM/")

    def test_lowercase_scheme(self) -> None:
        result = normalize_url("HTTPS://example.com/")
        assert result.startswith("https://")

    def test_removes_default_http_port(self) -> None:
        result = normalize_url("http://example.com:80/path")
        assert ":80" not in result
        assert "example.com" in result

    def test_removes_default_https_port(self) -> None:
        result = normalize_url("https://example.com:443/path")
        assert ":443" not in result

    def test_preserves_non_default_port(self) -> None:
        result = normalize_url("https://example.com:8443/path")
        assert ":8443" in result

    def test_empty_path_becomes_slash(self) -> None:
        result = normalize_url("https://example.com")
        assert result.endswith("/")

    def test_collapses_double_slashes_in_path(self) -> None:
        result = normalize_url("https://example.com//foo//bar")
        assert "//" not in result.split("?")[0].replace("https://", "")

    def test_fragment_removed(self) -> None:
        result = normalize_url("https://example.com/page#section")
        assert "#" not in result

    def test_query_preserved(self) -> None:
        result = normalize_url("https://example.com/search?q=test&lang=en")
        assert "q=test" in result
        assert "lang=en" in result

    def test_userinfo_preserved(self) -> None:
        result = normalize_url("https://user:pass@example.com/")
        assert "user" in result
        assert "example.com" in result

    def test_same_url_same_result(self) -> None:
        url = "https://Example.COM/Path?key=Value"
        assert normalize_url(url) == normalize_url(url)

    def test_case_insensitive_host_same_result(self) -> None:
        a = normalize_url("https://EXAMPLE.COM/path")
        b = normalize_url("https://example.com/path")
        assert a == b

    def test_default_port_equivalence(self) -> None:
        a = normalize_url("https://example.com:443/path")
        b = normalize_url("https://example.com/path")
        assert a == b


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


class TestHashing:
    def test_hash_is_sha256(self) -> None:
        url = "https://example.com/"
        expected = hashlib.sha256(url.encode("utf-8")).hexdigest()
        assert hash_url(url) == expected

    def test_hash_is_64_hex_chars(self) -> None:
        h = hash_url("https://example.com/")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_identical_normalized_urls_produce_identical_hash(self) -> None:
        a = normalize_url("https://EXAMPLE.COM/path")
        b = normalize_url("https://example.com/path")
        assert hash_url(a) == hash_url(b)

    def test_different_urls_produce_different_hashes(self) -> None:
        h1 = hash_url("https://example.com/")
        h2 = hash_url("https://other.com/")
        assert h1 != h2

    def test_hash_is_stable(self) -> None:
        url = "https://example.com/stable"
        # Call multiple times — must always return the same value
        hashes = {hash_url(url) for _ in range(10)}
        assert len(hashes) == 1
