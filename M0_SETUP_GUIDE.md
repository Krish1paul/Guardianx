# AI Personal Cybersecurity Guardian — M0 Foundation, Build-From-Scratch Guide

Follow this top to bottom on your own machine. It assumes Python 3.11+,
PostgreSQL, and Git are installed.

---

## 1. Create the folder structure

```bash
mkdir ai-cybersecurity-guardian && cd ai-cybersecurity-guardian

mkdir -p backend/app/{core,api/v1,models,schemas,services,db,middleware}
mkdir -p backend/tests
mkdir -p ml/{datasets,preprocessing,features,training,evaluation,models,inference,notebooks}
mkdir -p frontend data tests docs scripts docker

for d in ml/datasets ml/preprocessing ml/features ml/training ml/evaluation ml/models ml/inference ml/notebooks data frontend; do
  touch "$d/.gitkeep"
done

touch backend/app/schemas/__init__.py backend/app/services/__init__.py \
      backend/app/middleware/__init__.py backend/app/api/__init__.py \
      backend/app/api/v1/__init__.py backend/app/models/__init__.py \
      backend/app/core/__init__.py backend/app/db/__init__.py backend/app/__init__.py
```

(Note: if you're on `/bin/sh`, brace expansion `{a,b,c}` won't work — use `bash` explicitly or write each `mkdir` line out.)

---

## 2. `backend/pyproject.toml`

```toml
[project]
name = "ai-cybersecurity-guardian-backend"
version = "0.1.0"
description = "Backend for the AI Personal Cybersecurity Guardian platform"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "psycopg[binary]>=3.2.0",
    "pydantic>=2.8.0",
    "pydantic-settings>=2.4.0",
    "python-dotenv>=1.0.0",
    "bcrypt>=4.1.0",
    "python-jose[cryptography]>=3.3.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-cov>=5.0.0",
    "httpx>=0.27.0",
    "ruff>=0.6.0",
    "mypy>=1.11.0",
]

[tool.ruff]
line-length = 100
target-version = "py311"
src = ["app", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "N"]
ignore = []

[tool.mypy]
python_version = "3.11"
plugins = ["pydantic.mypy"]
strict = true
ignore_missing_imports = true
exclude = ["alembic/versions"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]

[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["app*"]
```

> Note on bcrypt: don't use `passlib[bcrypt]`. Passlib 1.7.4 is unmaintained
> and crashes (`ValueError: password cannot be longer than 72 bytes`) on
> current `bcrypt` releases (≥4.1) due to a broken internal self-test. Call
> the `bcrypt` library directly instead — see `core/security.py` below.

---

## 3. `backend/app/core/config.py`

```python
"""Application configuration.

Settings are loaded from environment variables (and a local .env file in
development). No secret ever has a real default value here -- production
deployments must fail fast if a required secret is missing.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = Field(default="development")

    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian",
    )

    jwt_secret: str = Field(default="")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_days: int = Field(default=7)

    cors_origins: str = Field(default="http://localhost:5173")

    @field_validator("environment")
    @classmethod
    def _validate_environment(cls, value: str) -> str:
        allowed = {"development", "test", "staging", "production"}
        if value not in allowed:
            raise ValueError(f"environment must be one of {allowed}, got {value!r}")
        return value

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def validate_production_secrets(self) -> None:
        if not self.is_production:
            return
        missing: list[str] = []
        if not self.jwt_secret or len(self.jwt_secret) < 32:
            missing.append("JWT_SECRET (must be set and at least 32 characters)")
        if "postgres:postgres@localhost" in self.database_url:
            missing.append("DATABASE_URL (must not use default local credentials)")
        if missing:
            raise RuntimeError(
                "Refusing to start in production with missing/insecure configuration: "
                + ", ".join(missing)
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

---

## 4. `backend/app/core/security.py`

```python
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
```

---

## 5. `backend/app/core/logging.py`

```python
"""Application logging configuration.

Passwords, JWTs, raw message content, and uploaded file contents must
never be logged. This module provides a redacting filter plus base setup.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

_REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = {
    "password", "password_hash", "jwt", "jwt_secret",
    "access_token", "refresh_token", "authorization",
    "raw_message", "raw_content", "file_content",
}


class RedactSensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for key in _SENSITIVE_KEYS:
            if hasattr(record, key):
                setattr(record, key, _REDACTED)
        record.msg = _redact_message(str(record.msg))
        return True


def _redact_message(message: str) -> str:
    lowered = message.lower()
    for key in _SENSITIVE_KEYS:
        if key in lowered:
            return f"{message.split('=')[0] if '=' in message else message} {_REDACTED}"
    return message


def configure_logging(environment: str) -> None:
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.addFilter(RedactSensitiveDataFilter())

    fmt = (
        "%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s"
        if environment == "production"
        else "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    handler.setFormatter(logging.Formatter(fmt))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO if environment == "production" else logging.DEBUG)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def safe_extra(**kwargs: Any) -> dict[str, Any]:
    for key in kwargs:
        if key.lower() in _SENSITIVE_KEYS:
            raise ValueError(f"Refusing to log sensitive key: {key}")
    return kwargs
```

---

## 6. `backend/app/db/base.py`

```python
"""SQLAlchemy declarative base."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
```

## 7. `backend/app/db/session.py`

```python
"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def create_db_engine(database_url: str | None = None) -> Engine:
    url = database_url or get_settings().database_url
    return create_engine(url, pool_pre_ping=True, future=True)


engine: Engine = create_db_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

---

## 8. `backend/app/models/user.py`

```python
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


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # No delete cascade: audit log rows must survive user deletion for
    # audit-trail integrity. The FK on AuditLog is ON DELETE SET NULL.
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
```

## 9. `backend/app/models/audit_log.py`

```python
"""Audit log model."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_user_id_created_at", "user_id", "created_at"),
        Index("ix_audit_logs_action", "action"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User | None"] = relationship(back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} actor={self.actor}>"
```

## 10. `backend/app/models/__init__.py`

```python
"""ORM models package.

Importing every model module here ensures Alembic's autogeneration sees
the full schema regardless of which module triggers the import.
"""

from app.models.audit_log import AuditLog
from app.models.user import User

__all__ = ["AuditLog", "User"]
```

---

## 11. `backend/app/schemas/health.py`

```python
from __future__ import annotations

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
```

## 12. `backend/app/api/deps.py`

```python
"""Shared FastAPI dependencies.

M0 scope: only the database session dependency. Auth dependencies arrive
in M1.
"""

from __future__ import annotations

from app.db.session import get_db

__all__ = ["get_db"]
```

## 13. `backend/app/api/v1/health.py`

```python
"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(status="ok")
```

## 14. `backend/app/api/v1/router.py`

```python
"""Aggregates all v1 API routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router)
```

---

## 15. `backend/app/middleware/security_headers.py`

```python
"""Baseline HTTP security headers middleware."""

from __future__ import annotations

from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"strict-origin-when-cross-origin"),
                        (b"x-permitted-cross-domain-policies", b"none"),
                    ]
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)
```

---

## 16. `backend/app/main.py`

```python
"""FastAPI application entrypoint."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.middleware.security_headers import SecurityHeadersMiddleware

settings = get_settings()
configure_logging(settings.environment)
logger = get_logger(__name__)


def create_app() -> FastAPI:
    settings.validate_production_secrets()

    app = FastAPI(
        title="AI Personal Cybersecurity Guardian",
        description="Privacy-first personal cybersecurity risk platform.",
        version="0.1.0",
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(api_router, prefix="/api/v1")
    # Also expose /health unprefixed for Docker/orchestrator health checks.
    app.include_router(health_router)

    logger.info("Application configured for environment=%s", settings.environment)
    return app


app = create_app()
```

---

## 17. Install dependencies

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
```

---

## 18. Set up PostgreSQL

```bash
# create dev + test databases and a postgres/postgres role (adjust to taste)
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'postgres';"
sudo -u postgres psql -c "CREATE DATABASE cyberguardian;"
sudo -u postgres psql -c "CREATE DATABASE cyberguardian_test;"
```

Confirm `pg_hba.conf` allows `host ... 127.0.0.1/32 scram-sha-256` (default on most installs) so the app can connect over TCP, not just via the `peer`-authenticated local socket.

---

## 19. `.env.example` (repo root)

```env
# Copy this file to .env and fill in real values for local development.
# NEVER commit a real .env file. Secrets in this file are placeholders only.

ENVIRONMENT=development
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian
JWT_SECRET=
CORS_ORIGINS=http://localhost:5173
```

## `backend/.env` (local only — do not commit)

```env
ENVIRONMENT=development
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian
JWT_SECRET=dev-only-placeholder-not-for-production-use-0000000000
CORS_ORIGINS=http://localhost:5173
```

## `backend/.env.test` (local only — do not commit)

```env
ENVIRONMENT=test
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian_test
JWT_SECRET=test-only-placeholder-not-for-production-use-0000000000
CORS_ORIGINS=http://localhost:5173
```

---

## 20. Alembic

```bash
cd backend
.venv/bin/alembic init alembic
```

Edit `alembic/env.py` — replace the top section:

```python
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings  # noqa: E402
from app.db.base import Base  # noqa: E402
import app.models  # noqa: E402,F401  (registers all model metadata)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

config.set_main_option("sqlalchemy.url", get_settings().database_url)
```

And in `run_migrations_online()`, change the `context.configure(...)` call to:

```python
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
```

In `alembic.ini`, delete/comment out the line:
```
sqlalchemy.url = driver://user:pass@localhost/dbname
```
(env.py sets it dynamically from `DATABASE_URL`.)

Generate and apply the migration:

```bash
.venv/bin/alembic revision --autogenerate -m "create users and audit_logs tables"
.venv/bin/alembic upgrade head

# also apply to the test DB
DATABASE_URL="postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian_test" \
  .venv/bin/alembic upgrade head
```

Verify:
```bash
sudo -u postgres psql -d cyberguardian -c '\d users'
sudo -u postgres psql -d cyberguardian -c '\d audit_logs'
```
You should see the FK `audit_logs_user_id_fkey ... ON DELETE SET NULL` and the unique index on `users.email`.

---

## 21. Tests

### `backend/tests/conftest.py`

```python
"""Shared pytest fixtures.

Tests always run against the isolated test database (cyberguardian_test
via .env.test), never the developer's normal database. Each test runs in
a transaction that's rolled back afterward.
"""

from __future__ import annotations

import os
from collections.abc import Generator

os.environ.setdefault("ENVIRONMENT", "test")
if os.environ.get("ENVIRONMENT") != "test":
    raise RuntimeError("Tests must run with ENVIRONMENT=test to protect the dev database.")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import create_db_engine


@pytest.fixture(scope="session", autouse=True)
def _enforce_test_database() -> None:
    settings = get_settings()
    if "test" not in settings.database_url:
        pytest.exit(
            "Refusing to run tests: DATABASE_URL does not look like a test "
            f"database ({settings.database_url!r}). Aborting to protect developer data."
        )


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_db_engine()
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True, scope="session")
def _verify_test_db_reachable() -> None:
    engine = create_db_engine()
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
```

### `backend/tests/test_health.py`

```python
from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_returns_200(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200


def test_health_returns_status_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.json() == {"status": "ok"}
```

### `backend/tests/test_database.py`

```python
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def test_database_connection_can_be_established(db_session: Session) -> None:
    result = db_session.execute(text("SELECT 1")).scalar_one()
    assert result == 1
```

### `backend/tests/test_models.py`

```python
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models.audit_log import AuditLog
from app.models.user import User


def test_user_can_be_persisted(db_session: Session) -> None:
    user = User(email="test@example.com", password_hash=hash_password("correct horse battery"))
    db_session.add(user)
    db_session.flush()

    fetched = db_session.get(User, user.id)
    assert fetched is not None
    assert fetched.email == "test@example.com"
    assert fetched.mfa_enabled is False
    assert fetched.last_login_at is None
    assert fetched.password_hash != "correct horse battery"
    assert verify_password("correct horse battery", fetched.password_hash)


def test_user_email_must_be_unique(db_session: Session) -> None:
    db_session.add(User(email="dup@example.com", password_hash=hash_password("password123456")))
    db_session.flush()

    db_session.add(User(email="dup@example.com", password_hash=hash_password("password654321")))
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_audit_log_relationship_to_user(db_session: Session) -> None:
    user = User(email="audit@example.com", password_hash=hash_password("password123456"))
    db_session.add(user)
    db_session.flush()

    log = AuditLog(
        user_id=user.id,
        actor=user.email,
        action="LOGIN_SUCCESS",
        resource="auth",
        ip_address="127.0.0.1",
    )
    db_session.add(log)
    db_session.flush()
    db_session.refresh(user)

    assert log.user_id == user.id
    assert log.user is user
    assert log in user.audit_logs


def test_audit_log_user_id_is_nullable(db_session: Session) -> None:
    log = AuditLog(
        user_id=None,
        actor="anonymous",
        action="LOGIN_FAILED",
        resource="auth",
        ip_address="10.0.0.1",
    )
    db_session.add(log)
    db_session.flush()

    assert log.id is not None
    assert log.user_id is None
```

Run tests:

```bash
cd backend
ENVIRONMENT=test \
DATABASE_URL="postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian_test" \
JWT_SECRET="test-only-placeholder-not-for-production-use-0000000000" \
.venv/bin/pytest -v
```

All 7 tests (2 health + 1 db + 4 model) should pass.

---

## 22. Lint & type-check

```bash
.venv/bin/ruff check .
.venv/bin/mypy .
```

Fix anything that comes up rather than disabling rules. (Common early fix: add missing `from __future__ import annotations` or return types if mypy strict flags them.)

---

## 23. `docker-compose.yml` (repo root)

```yaml
services:
  db:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: cyberguardian
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: ./backend
      dockerfile: ../docker/backend.Dockerfile
    restart: unless-stopped
    env_file:
      - ./backend/.env
    environment:
      DATABASE_URL: postgresql+psycopg://postgres:postgres@db:5432/cyberguardian
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

### `docker/backend.Dockerfile`

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 24. `.gitignore` (repo root)

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
*.egg-info/

# Env
.env
.env.*
!.env.example

# ML artifacts / data
ml/models/*.pkl
data/*
!data/.gitkeep

# Node / frontend
frontend/node_modules/
frontend/dist/

# IDE / OS
.vscode/
.idea/
.DS_Store

# Test/coverage
.pytest_cache/
.coverage
htmlcov/
.mypy_cache/
.ruff_cache/
```

---

## 25. Docs stubs

Create `docs/architecture.md`, `docs/database.md`, `docs/development-roadmap.md`, and `docs/threat-model.md`, documenting exactly what's been approved and built so far (system/component/DB/API/ML/security architecture from the architecture-approval message, the M0–M11 roadmap, and the threat model summary: attackers, assets, attack surface, mitigations). Don't describe features that don't exist yet — keep each doc scoped to what's actually implemented plus the agreed future plan.

---

## 26. Root `README.md`

Include: project name, problem statement, goals, architecture summary, tech stack, repo structure, local setup steps (venv install, Postgres setup, `.env` copy, alembic upgrade, `uvicorn app.main:app --reload`), Docker setup (`docker compose up`), environment variables table, how to run tests/lint/mypy, and a clearly stated **Current status: M0 — Foundation** plus the M0–M11 roadmap list.

---

## 27. Git

```bash
cd ai-cybersecurity-guardian
git init
git add .
git commit -m "feat: initialize cybersecurity guardian foundation"
```

---

## 28. Final verification checklist

```bash
docker compose up            # or run Postgres + uvicorn locally
alembic upgrade head
pytest
ruff check .
mypy .
```

All should pass cleanly before you consider M0 done. Do not start M1 (Authentication) until this is fully green.
