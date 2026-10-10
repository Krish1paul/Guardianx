"""Application logging configuration.

Passwords, JWTs, raw message content, uploaded file contents, API keys,
and sensitive query parameters must never be logged. This module provides
a redacting filter and formatter plus base setup with correlation ID tracing.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

from app.middleware.correlation_id import get_correlation_id

_REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "jwt",
    "jwt_secret",
    "access_token",
    "refresh_token",
    "authorization",
    "raw_message",
    "raw_content",
    "file_content",
    # M4 — TI provider credentials
    "virustotal_api_key",
    "x-apikey",
    "apikey",
    "api_key",
    # M5 — query and token parameters
    "secret",
    "token",
    "auth",
    "signature",
    "sig",
}

# Regex to redact sensitive query parameters in URLs (e.g. ?token=xyz or &key=abc)
_QUERY_PARAM_REDACT_RE = re.compile(
    r"([?&](?:token|key|api_key|apikey|password|secret|auth|jwt|signature|sig)=)([^&\s]+)",
    re.IGNORECASE,
)

# Regex to redact Bearer tokens (e.g. Bearer eyJhbGciOi...)
_BEARER_REDACT_RE = re.compile(
    r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*",
    re.IGNORECASE,
)

# Regex to redact Authorization header values (e.g. Authorization: Basic xyz or Authorization: xyz)
_AUTH_HEADER_REDACT_RE = re.compile(
    r"(\bauthorization\s*[:=]\s*(?:Bearer\s+)?)([^\s,]+)",
    re.IGNORECASE,
)

# Regex to redact sensitive key-value pairs (e.g. password=secret or api_key: xyz)
_KEY_VALUE_REDACT_RE = re.compile(
    r"(\b(?:password|password_hash|jwt|jwt_secret|access_token|refresh_token|"
    r"virustotal_api_key|x-apikey|apikey|api_key|secret)\s*[:=]\s*)([^\s,]+)",
    re.IGNORECASE,
)


class RedactSensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Attach correlation_id if available
        cid = get_correlation_id()
        record.correlation_id = cid if cid else "-"

        for key in _SENSITIVE_KEYS:
            if hasattr(record, key):
                setattr(record, key, _REDACTED)
        return True


def _redact_message(message: str) -> str:
    # 1. Redact URL query parameters
    message = _QUERY_PARAM_REDACT_RE.sub(r"\1" + _REDACTED, message)
    # 2. Redact Bearer tokens
    message = _BEARER_REDACT_RE.sub(r"\1" + _REDACTED, message)
    # 3. Redact Authorization header values if not already Bearer
    message = _AUTH_HEADER_REDACT_RE.sub(r"\1" + _REDACTED, message)
    # 4. Redact key-value credentials
    message = _KEY_VALUE_REDACT_RE.sub(r"\1" + _REDACTED, message)
    return message


class RedactingFormatter(logging.Formatter):
    """Custom logging formatter that applies message redaction to the final string."""

    def format(self, record: logging.LogRecord) -> str:
        s = super().format(record)
        return _redact_message(s)


def configure_logging(environment: str) -> None:
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.addFilter(RedactSensitiveDataFilter())

    fmt = (
        "%(asctime)s level=%(levelname)s correlation_id=%(correlation_id)s "
        "logger=%(name)s msg=%(message)s"
        if environment == "production"
        else "%(asctime)s [%(levelname)s] [%(correlation_id)s] %(name)s: %(message)s"
    )
    handler.setFormatter(RedactingFormatter(fmt))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO if environment == "production" else logging.DEBUG)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def safe_extra(**kwargs: Any) -> dict[str, Any]:
    for key in kwargs:
        if key.lower() in _SENSITIVE_KEYS:
            raise ValueError(f"Refusing to log sensitive key: {key}")
    return kwargs
