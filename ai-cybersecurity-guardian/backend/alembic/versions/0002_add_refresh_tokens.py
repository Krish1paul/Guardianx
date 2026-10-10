"""Add refresh_tokens table — M1 Authentication.

Revision ID: 0002
Revises:     0001
Create Date: 2026-08-22 00:00:00.000000 UTC

Security notes
--------------
- ``token_hash`` stores only SHA-256(jti) — never the raw JWT or JTI.
- ``family_id`` groups a rotation chain; reuse of any consumed token in the
  family triggers revocation of all active tokens in that family.
- ON DELETE CASCADE: if a user is deleted, their refresh tokens are removed.
  (Contrast with audit_logs which use ON DELETE SET NULL to preserve history.)
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "refresh_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # SHA-256 hex digest (64 chars) of the JWT's jti claim.
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        # UUID grouping a rotation chain.
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # NULL = active.  Non-NULL = revoked/consumed.
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Unique index on token_hash — the primary lookup key.
    op.create_index(
        "ix_refresh_tokens_token_hash",
        "refresh_tokens",
        ["token_hash"],
        unique=True,
    )
    # For querying all tokens belonging to a user (e.g. logout-all-sessions).
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    # For family revocation queries.
    op.create_index(
        "ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_token_hash", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
