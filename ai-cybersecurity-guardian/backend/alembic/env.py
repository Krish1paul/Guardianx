"""Alembic environment configuration.

This module:
- Reads DATABASE_URL from the environment (via app.core.config).
- Imports all ORM models so autogenerate sees the full schema.
- Runs migrations synchronously (psycopg3 sync driver).
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ---------------------------------------------------------------------------
# Import the shared declarative Base and all model modules so that
# Base.metadata contains every table.
# ---------------------------------------------------------------------------
from app.db.base import Base
import app.models  # noqa: F401  — side-effect import registers all models

# ---------------------------------------------------------------------------
# Alembic Config object — gives access to the values in alembic.ini.
# ---------------------------------------------------------------------------
config = context.config

# Apply logging configuration from alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Override sqlalchemy.url from the environment variable or Settings.
# This ensures the app's pydantic-settings value is always used.
# ---------------------------------------------------------------------------
from app.core.config import get_settings

database_url = os.environ.get("DATABASE_URL") or get_settings().database_url
if database_url:
    config.set_main_option("sqlalchemy.url", database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine, though an
    Engine is acceptable here as well.  By skipping the Engine creation we
    don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the script
    output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a connection
    with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
