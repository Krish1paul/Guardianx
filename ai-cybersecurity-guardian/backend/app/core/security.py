"""Security primitives shared across the application.

M0 scope: password hashing utilities only. JWT issuance/verification is
deferred to M1 — Authentication.
"""

from __future__ import annotations

import bcrypt

_MAX_PASSWORD_BYTES = 72
_BCRYPT_ROUNDS = 12


def hash_password(plain_password: str) -> str:
    if not plain_password:
        raise ValueError("Password must not be empty.")
    password_bytes = plain_password.encode("utf-8")
    if len(password_bytes) > _MAX_PASSWORD_BYTES:
        raise ValueError("Password exceeds maximum supported length.")
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False
