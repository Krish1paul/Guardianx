"""Authentication API endpoints — M1.

Endpoints
---------
POST  /api/v1/auth/register  — Create a new user account.
POST  /api/v1/auth/login     — Authenticate; receive access + refresh tokens.
POST  /api/v1/auth/refresh   — Rotate the refresh token; receive a new token pair.
POST  /api/v1/auth/logout    — Revoke the refresh token.
GET   /api/v1/auth/me        — Return information about the current user.

Rate limiting
-------------
register, login, and refresh are rate-limited per source IP using the
in-memory sliding-window limiter (see ``app/core/rate_limit.py``).
Tests inject ``UnlimitedRateLimiter`` via ``dependency_overrides``.

Access-token revocation
------------------------
Access tokens are NOT revocable server-side.  Their short lifetime
(default 15 minutes) is the mitigation.  Server-side revocation via a
Redis blocklist is deferred to M5 (Production Hardening).
"""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.auth import TokenType, decode_token
from app.core.config import get_settings
from app.core.rate_limit import make_rate_limit_dep
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserMeResponse,
)
from app.services.auth import (
    AuthService,
    EmailAlreadyRegisteredError,
    InvalidCredentialsError,
    TokenNotFoundError,
    TokenReuseError,
)
from app.services.token_revocation import (
    TokenRevocationService,
    get_token_revocation_service,
)

router = APIRouter(prefix="/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)

# Rate-limit dependencies — one per endpoint, keyed separately so limits are
# tracked independently.  Override ``get_limiter`` in tests.
_settings = get_settings()

_register_rl = make_rate_limit_dep(
    "auth:register",
    limit=_settings.rate_limit_register,
    window_seconds=60,
)
_login_rl = make_rate_limit_dep(
    "auth:login",
    limit=_settings.rate_limit_login,
    window_seconds=60,
)
_refresh_rl = make_rate_limit_dep(
    "auth:refresh",
    limit=_settings.rate_limit_refresh,
    window_seconds=60,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_ip(request: Request) -> str | None:
    """Extract the client IP from the request.

    In production behind a reverse proxy, consult X-Real-IP / X-Forwarded-For.
    For M1 (direct uvicorn), request.client.host is sufficient.
    """
    return request.client.host if request.client else None


def _auth_svc(db: Session) -> AuthService:
    return AuthService(db)


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=UserMeResponse,
    summary="Register a new user account",
)
def register(
    body: RegisterRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    _rl: Annotated[None, Depends(_register_rl)],
) -> UserMeResponse:
    """Create a new user account.

    - Email is validated (RFC 5322) and normalised to lowercase.
    - Password is validated for strength before hashing.
    - Duplicate email returns 409 without leaking account existence details
      beyond what is appropriate for a registration flow.
    - A ``auth.register.success`` audit event is created on success.
    """
    try:
        user = _auth_svc(db).register(
            email=body.email,
            password=body.password,
            ip_address=_client_ip(request),
        )
    except EmailAlreadyRegisteredError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        ) from None
    return UserMeResponse.model_validate(user)


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


@router.post(
    "/login",
    response_model=TokenPair,
    summary="Authenticate and receive a token pair",
)
def login(
    body: LoginRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    _rl: Annotated[None, Depends(_login_rl)],
) -> TokenPair:
    """Authenticate with email and password.

    Returns a short-lived access token (default 15 min) and a longer-lived
    refresh token.  The access token is a signed JWT; the refresh token is
    a signed JWT whose ``jti`` is stored (hashed) server-side.

    Both wrong email and wrong password return the same 401 response to
    prevent account enumeration.
    """
    try:
        return _auth_svc(db).login(
            email=body.email,
            password=body.password,
            ip_address=_client_ip(request),
        )
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Rotate the refresh token",
)
def refresh(
    body: RefreshRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    _rl: Annotated[None, Depends(_refresh_rl)],
) -> TokenPair:
    """Rotate the refresh token and return a new token pair.

    The old refresh token is atomically revoked and a new one issued in a
    single database transaction.

    If a previously-consumed token is presented (reuse detected), the entire
    token family is revoked, all sessions for the user are invalidated, and
    a ``security.refresh.reuse_detected`` audit event is recorded.
    """
    try:
        return _auth_svc(db).refresh(
            refresh_token_str=body.refresh_token,
            ip_address=_client_ip(request),
        )
    except TokenReuseError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked. Please log in again.",
        ) from None
    except (TokenNotFoundError, Exception):
        # TokenExpiredError, TokenInvalidError, TokenTypeError, TokenError
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        ) from None


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke the refresh token and end the session",
)
def logout(
    body: LogoutRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    revocation_service: Annotated[TokenRevocationService, Depends(get_token_revocation_service)],
) -> None:
    """Revoke the provided refresh token and blacklist the active access token.

    - The access token's JTI is placed in the Redis revocation blocklist with a
      TTL matching its remaining lifetime.
    - The refresh token record in the database is marked revoked.
    - Providing an already-invalid or expired refresh token still succeeds;
      user intent (logout) is honoured regardless.
    """
    if credentials is not None:
        try:
            payload = decode_token(credentials.credentials, expected_type=TokenType.ACCESS)
            jti = str(payload.get("jti", ""))
            exp = float(payload.get("exp", time.time() + 900))
            ttl = int(exp - time.time())
            if jti:
                revocation_service.revoke_token(jti, ttl_seconds=ttl)
        except Exception:
            pass

    _auth_svc(db).logout(
        refresh_token_str=body.refresh_token,
        user_id=current_user.id,
        ip_address=_client_ip(request),
    )


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


@router.get(
    "/me",
    response_model=UserMeResponse,
    summary="Return information about the authenticated user",
)
def me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserMeResponse:
    """Return safe profile information for the currently authenticated user.

    Never returns: ``password_hash``, refresh tokens, or internal secrets.
    """
    return UserMeResponse.model_validate(current_user)
