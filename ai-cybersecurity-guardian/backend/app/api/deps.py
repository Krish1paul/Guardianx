"""Shared FastAPI dependencies.

M0: database session dependency.
M1: authenticated-user dependency (get_current_user).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.auth import TokenError, TokenType, decode_token
from app.db.session import get_db
from app.models.user import User
from app.services.token_revocation import (
    TokenRevocationService,
    get_token_revocation_service,
)

__all__ = ["get_current_user", "get_db"]

# HTTPBearer with auto_error=False so we can return a clean 401 ourselves
# rather than letting FastAPI produce an unformatted 403.
_bearer = HTTPBearer(auto_error=False)


def _unauthorized(detail: str = "Not authenticated.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
    revocation_service: Annotated[TokenRevocationService, Depends(get_token_revocation_service)],
) -> User:
    """FastAPI dependency: extract, validate, and verify the Bearer access token.

    Steps:
      1. Extract the Authorization: Bearer <token> header.
      2. Decode and validate the JWT (signature, expiry, required claims).
      3. Validate token type == "access".
      4. Verify token JTI is not in the revocation blocklist.
      5. Resolve the user from the database.

    Raises:
      HTTP 401 for any of:
        - Missing Authorization header.
        - Malformed / expired / invalid token.
        - Wrong token type (e.g. refresh token passed here).
        - Revoked token JTI.
        - User not found (treats as invalid token — never reveals account existence).
    """
    if credentials is None:
        raise _unauthorized()

    try:
        payload = decode_token(credentials.credentials, expected_type=TokenType.ACCESS)
    except TokenError:
        raise _unauthorized() from None

    jti = payload.get("jti")
    if not jti or revocation_service.is_token_revoked(str(jti)):
        raise _unauthorized(detail="Token has been revoked.")

    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (ValueError, KeyError):
        raise _unauthorized() from None

    user = db.get(User, user_id)
    if user is None:
        raise _unauthorized()

    return user
