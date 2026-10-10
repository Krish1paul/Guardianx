"""Add threat_intelligence_results table — M4.

Revision ID: 0004
Revises:     0003
Create Date: 2026-08-29 00:00:00.000000 UTC

Schema notes
------------
-  Separate table — ``url_scans`` rows are NEVER modified.
-  ``scan_id`` is UNIQUE (one TI result per scan) and FK → url_scans.id
   with ON DELETE CASCADE.
-  ``confidence`` is nullable (provider may not report a confidence value).
-  ``reason`` is nullable (TEXT — provider reason string, may be long).
-  ``status``: VARCHAR(20) — "CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN".
-  ``provider_error``: BOOLEAN — true when the provider call failed.
-  ``cached``: BOOLEAN — true when served from in-memory cache.
-  ``checked_at``: TIMESTAMPTZ — when the query was made.

Indexes
-------
-  ``ix_ti_scan_id``: lookup by scan_id (also enforces uniqueness).
-  ``ix_ti_provider``: lookup by provider name (useful for analytics).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_intelligence_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("url_scans.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        # e.g. "virustotal", "mock"
        sa.Column("provider", sa.String(64), nullable=False),
        # "CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"
        sa.Column("status", sa.String(20), nullable=False),
        # Confidence [0.0, 1.0]; nullable
        sa.Column("confidence", sa.Float, nullable=True),
        # Human-readable provider reason; nullable, may be long
        sa.Column("reason", sa.Text, nullable=True),
        # True when result was served from in-memory cache
        sa.Column("cached", sa.Boolean, nullable=False, server_default="false"),
        # True when provider call failed
        sa.Column("provider_error", sa.Boolean, nullable=False, server_default="false"),
        # UTC timestamp of the TI query
        sa.Column(
            "checked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # Index: lookup by scan_id
    op.create_index("ix_ti_scan_id", "threat_intelligence_results", ["scan_id"])

    # Index: filter/aggregate by provider
    op.create_index("ix_ti_provider", "threat_intelligence_results", ["provider"])


def downgrade() -> None:
    op.drop_index("ix_ti_provider", table_name="threat_intelligence_results")
    op.drop_index("ix_ti_scan_id", table_name="threat_intelligence_results")
    op.drop_table("threat_intelligence_results")
