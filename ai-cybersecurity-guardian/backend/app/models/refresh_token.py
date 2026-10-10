"""RefreshToken model — M1 Authentication.

Security design
---------------
Raw refresh JWTs are **never stored** in this table.
Only ``SHA-256(jti)`` is persisted in ``token_hash``.

If the database is compromised, the attacker obtains only hashed token IDs.
They cannot reconstruct valid JWTs because:
  1. SHA-256 is a one-way function.
  2. Each JTI is a UUID4 (128 bits of entropy) — not brute-forceable.

Token family (``family_id``)
-----------------------------
All tokens issued within a single rotation chain share the same
``family_id``.  If a consumed/revoked token is presented again (reuse
detected), the entire family is revoked, logging out all sessions for that
user.  This prevents silent session hijacking after token theft.

Lifecycle
---------
    1. Login creates a new token with a new ``family_id``.
    2. Refresh revokes the old token (sets ``revoked_at``) and issues a new
       token with the same ``family_id``.
    3. Logout sets ``revoked_at`` on the active token.
    4. Reuse detection (``revoked_at IS NOT NULL``) triggers family revocation.
    5. Rows with ``expires_at < now()`` are logically expired regardless of
       ``revoked_at``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_token_hash", "token_hash", unique=True),
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_family_id", "family_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # SHA-256(jti) — the raw token or raw JTI is NEVER stored.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Groups a rotation chain.  Reuse of any token in the family revokes all.
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # NULL means active.  Set to current UTC when revoked/consumed.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")

    @property
    def is_active(self) -> bool:
        """Return True if the token has not been revoked and has not expired."""
        return self.revoked_at is None and self.expires_at.replace(tzinfo=UTC) > datetime.now(UTC)

    def __repr__(self) -> str:
        return (
            f"<RefreshToken id={self.id} user_id={self.user_id} "
            f"family={self.family_id} active={self.is_active}>"
        )
