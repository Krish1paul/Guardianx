"""Authentication request/response schemas — M1.

Schema separation
-----------------
- ``RegisterRequest`` / ``LoginRequest``  : inbound data (validated + normalised)
- ``TokenPair``                           : outbound token envelope
- ``RefreshRequest`` / ``LogoutRequest``  : bodies for token rotation/revocation
- ``UserMeResponse``                      : safe user representation

Security:
- ``password_hash`` is never included in any response schema.
- Raw tokens are never logged — schemas only appear in request/response bodies.
- Email is normalised to lowercase on ingestion to prevent duplicate accounts.

Password policy (``RegisterRequest``):
- Minimum 8 characters.
- Maximum 72 characters (bcrypt hard limit — longer bytes are silently truncated).
- Must contain at least one uppercase letter.
- Must contain at least one lowercase letter.
- Must contain at least one digit.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_PASSWORD_LEN = 8
_MAX_PASSWORD_BYTES = 72  # bcrypt silently truncates beyond this


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_password_strength(value: str) -> str:
    if len(value) < _MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LEN} characters long.")
    if len(value.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must not exceed {_MAX_PASSWORD_BYTES} bytes.")
    if not any(c.isupper() for c in value):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in value):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in value):
        raise ValueError("Password must contain at least one digit.")
    return value


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    """Registration body — email + plaintext password."""

    email: EmailStr
    password: str

    @field_validator("email", mode="after")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        """Lowercase and strip — prevents duplicate accounts via case variation."""
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _check_password_strength(v)


class LoginRequest(BaseModel):
    """Login body — email + plaintext password."""

    email: EmailStr
    password: str

    @field_validator("email", mode="after")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.strip().lower()


class RefreshRequest(BaseModel):
    """Token refresh body — the current refresh JWT."""

    refresh_token: str


class LogoutRequest(BaseModel):
    """Logout body — the refresh JWT to revoke."""

    refresh_token: str


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class TokenPair(BaseModel):
    """Access + refresh token pair returned by login and refresh endpoints."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserMeResponse(BaseModel):
    """Safe user representation.

    Deliberately excludes: ``password_hash``, raw tokens, internal flags.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    created_at: datetime
    mfa_enabled: bool
    last_login_at: datetime | None
