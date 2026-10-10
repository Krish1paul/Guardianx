"""JWT token creation and verification — M1 Authentication.

Token structure
---------------
Both access and refresh tokens share the same claim set:

    {
      "sub":  str,   # User UUID (stringified)
      "type": str,   # "access" | "refresh"
      "iat":  int,   # Issued-at (UTC epoch seconds)
      "exp":  int,   # Expires-at (UTC epoch seconds)
      "jti":  str,   # UUID4 — unique token ID used for revocation
    }

Refresh token persistence
--------------------------
Raw refresh JWTs are **never stored**.  Only ``SHA-256(jti)`` is persisted
in the ``refresh_tokens`` table.  A full DB compromise therefore cannot yield
replayable tokens.

Security notes
--------------
- Tokens are signed with HS256 using ``JWT_SECRET`` from env configuration.
- ``JWT_SECRET`` must be ≥ 32 characters in production (enforced at startup).
- Sensitive claims (passwords, roles, PII) are never embedded in tokens.
- Access tokens are short-lived (default 15 min) and not server-side revocable.
  Short lifetime is the mitigation; server-side revocation is an M5 concern.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidTokenError

from app.core.config import get_settings

_ALGORITHM = "HS256"


class TokenType:
    ACCESS = "access"
    REFRESH = "refresh"


# ---------------------------------------------------------------------------
# Domain exceptions — translated to HTTP errors at the router layer.
# ---------------------------------------------------------------------------


class TokenError(Exception):
    """Base exception for all token validation failures."""


class TokenExpiredError(TokenError):
    """JWT signature is valid but the token has passed its expiry time."""


class TokenInvalidError(TokenError):
    """JWT is malformed, signature is wrong, or a required claim is absent."""


class TokenTypeError(TokenError):
    """Token ``type`` claim does not match the expected value."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------


def create_access_token(user_id: uuid.UUID) -> str:
    """Return a signed access token for *user_id*."""
    settings = get_settings()
    now = _utc_now()
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": TokenType.ACCESS,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALGORITHM)


def create_refresh_token(user_id: uuid.UUID) -> tuple[str, str, datetime]:
    """Return ``(raw_jwt, jti, expires_at)`` for a new refresh token.

    The caller **must** persist only ``hash_jti(jti)``, not ``raw_jwt``.

    Returns:
        raw_jwt:    Full signed token string — send to the client.
        jti:        Token ID string — hash before storing.
        expires_at: UTC-aware expiry datetime — store in the DB.
    """
    settings = get_settings()
    now = _utc_now()
    expire = now + timedelta(days=settings.refresh_token_expire_days)
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": TokenType.REFRESH,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": jti,
    }
    raw_token = jwt.encode(payload, settings.jwt_secret, algorithm=_ALGORITHM)
    return raw_token, jti, expire


# ---------------------------------------------------------------------------
# JTI hashing
# ---------------------------------------------------------------------------


def hash_jti(jti: str) -> str:
    """Return the SHA-256 hex digest of *jti*.

    This value — and only this value — is stored in the database.
    """
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


def decode_token(token: str, expected_type: str) -> dict[str, Any]:
    """Decode and validate a JWT, returning its payload.

    Args:
        token:         Raw JWT string (from Authorization header or request body).
        expected_type: Required value of the ``type`` claim.

    Raises:
        TokenExpiredError:  Token has passed its ``exp`` timestamp.
        TokenInvalidError:  Malformed token, bad signature, or missing claim.
        TokenTypeError:     ``type`` claim does not match *expected_type*.
    """
    settings = get_settings()
    try:
        payload: dict[str, Any] = jwt.decode(token, settings.jwt_secret, algorithms=[_ALGORITHM])
    except ExpiredSignatureError:
        raise TokenExpiredError("Token has expired.") from None
    except (DecodeError, InvalidTokenError) as exc:
        raise TokenInvalidError(f"Token is invalid: {exc}") from exc

    for required in ("sub", "type", "jti"):
        if required not in payload:
            raise TokenInvalidError(f"Missing required claim: '{required}'.")

    if payload["type"] != expected_type:
        raise TokenTypeError(f"Expected token type '{expected_type}', got '{payload['type']}'.")

    return payload
