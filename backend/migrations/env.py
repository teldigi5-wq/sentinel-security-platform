"""Sentinel migrations: never load application secrets or print DB credentials."""
from logging.config import fileConfig
import os
from alembic import context
from sqlalchemy import engine_from_config, pool
from sentinel.models import Base

config = context.config
target_metadata = Base.metadata


def _database_url() -> str:
    url = config.attributes.get("database_url") or os.environ.get("SENTINEL_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    if not isinstance(url, str) or not url.startswith(("sqlite:", "postgresql+psycopg:")):
        raise RuntimeError("Invalid Sentinel migration database URL")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_database_url(), target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={"paramstyle": "named"}, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
