"""Add message_scans and file_scans tables — M7.

Revision ID: 0005
Revises:     0004
Create Date: 2026-09-10 00:00:00.000000 UTC

Multi-Vector Threat Detection:
- message_scans: Persists message threat/phishing assessments without storing raw message contents.
- file_scans: Persists safe static file inspection records without storing permanent file contents.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -----------------------------------------------------------------------
    # Table: message_scans
    # -----------------------------------------------------------------------
    op.create_table(
        "message_scans",
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
        sa.Column("message_hash", sa.String(64), nullable=False),
        sa.Column("subject", sa.String(500), nullable=True),
        sa.Column("sender", sa.String(255), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("classification", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column(
            "features",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column(
            "reasons",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column(
            "extracted_urls",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column("analyzer_version", sa.String(32), nullable=False, server_default="message-v1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_message_scans_user_id", "message_scans", ["user_id"])
    op.create_index("ix_message_scans_message_hash", "message_scans", ["message_hash"])

    # -----------------------------------------------------------------------
    # Table: file_scans
    # -----------------------------------------------------------------------
    op.create_table(
        "file_scans",
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
        sa.Column("file_hash", sa.String(64), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("detected_type", sa.String(64), nullable=False),
        sa.Column("declared_mime", sa.String(128), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("classification", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column(
            "features",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column(
            "reasons",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column("analyzer_version", sa.String(32), nullable=False, server_default="file-v1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_file_scans_user_id", "file_scans", ["user_id"])
    op.create_index("ix_file_scans_file_hash", "file_scans", ["file_hash"])


def downgrade() -> None:
    op.drop_index("ix_file_scans_file_hash", table_name="file_scans")
    op.drop_index("ix_file_scans_user_id", table_name="file_scans")
    op.drop_table("file_scans")

    op.drop_index("ix_message_scans_message_hash", table_name="message_scans")
    op.drop_index("ix_message_scans_user_id", table_name="message_scans")
    op.drop_table("message_scans")
