"""User model."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.file_scan import FileScan
    from app.models.incident import Incident
    from app.models.message_scan import MessageScan
    from app.models.refresh_token import RefreshToken
    from app.models.url_scan import URLScan


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # No delete cascade: audit log rows must survive user deletion for
    # audit-trail integrity. The FK on AuditLog is ON DELETE SET NULL.
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user")
    # Refresh tokens are deleted when the user is deleted (CASCADE).
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    # URL scans are deleted when the user is deleted (CASCADE).
    url_scans: Mapped[list[URLScan]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    # M7 — Message scans are deleted when the user is deleted (CASCADE).
    message_scans: Mapped[list[MessageScan]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    # M7 — File scans are deleted when the user is deleted (CASCADE).
    file_scans: Mapped[list[FileScan]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    # M8 — Incidents are deleted when the user is deleted (CASCADE).
    incidents: Mapped[list[Incident]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
