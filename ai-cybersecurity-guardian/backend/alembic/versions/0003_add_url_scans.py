"""Add url_scans table — M2 URL Threat Analyzer.

Revision ID: 0003
Revises:     0002
Create Date: 2026-08-22 00:00:00.000000 UTC

Schema notes
------------
- ``url_hash``: SHA-256 hex digest (64 chars) of the normalized URL.
  Indexed for deduplication queries.  Never the raw URL.
- ``normalized_url``: Stored plaintext for UX (history display).
  Privacy decision documented in app/models/url_scan.py.
- ``features``, ``reasons``: JSONB for efficient querying and indexing
  on PostgreSQL.  JSON on SQLite (used in tests only).
- ``analyzer_version``: "rule-v1" for M2.  M3 inserts "ml-v1".
  Historical rows are never updated — version is immutable.
- ON DELETE CASCADE: removing a user removes their scans.

Indexes
-------
- ``ix_url_scans_user_id``: all scans belonging to a user.
- ``ix_url_scans_url_hash``: lookup / deduplication by URL hash.
- ``ix_url_scans_user_id_created_at``: composite for history queries
  (user_id + newest-first ordering).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "url_scans",
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
        # SHA-256 hex digest (64 chars) of the normalized URL.
        sa.Column("url_hash", sa.String(64), nullable=False),
        # Normalized URL stored plaintext — see privacy decision in model file.
        sa.Column("normalized_url", sa.Text, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("classification", sa.String(20), nullable=False),
        # JSONB for structured querying on PostgreSQL.
        sa.Column("features", postgresql.JSONB, nullable=False),
        sa.Column("reasons", postgresql.JSONB, nullable=False),
        # Analyzer version — immutable after insert.
        sa.Column("analyzer_version", sa.String(32), nullable=False, server_default="rule-v1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # Index: lookup scans by user_id
    op.create_index("ix_url_scans_user_id", "url_scans", ["user_id"])

    # Index: lookup / deduplication by URL hash
    op.create_index("ix_url_scans_url_hash", "url_scans", ["url_hash"])

    # Composite index: history queries (user_id + newest-first)
    op.create_index(
        "ix_url_scans_user_id_created_at",
        "url_scans",
        ["user_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_url_scans_user_id_created_at", table_name="url_scans")
    op.drop_index("ix_url_scans_url_hash", table_name="url_scans")
    op.drop_index("ix_url_scans_user_id", table_name="url_scans")
    op.drop_table("url_scans")
