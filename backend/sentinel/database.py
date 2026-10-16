"""Explicit, fail-closed Alembic schema handling."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy.engine import Engine

HEAD_REVISION = "0002_audit_head"


def alembic_config(url: str) -> Config:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    # Alembic configuration attributes avoid interpolating percent signs in URLs.
    config.attributes["database_url"] = url
    return config


def migrate(url: str) -> None:
    command.upgrade(alembic_config(url), "head")


def verify_schema(engine: Engine) -> None:
    with engine.connect() as conn:
        revision = MigrationContext.configure(conn).get_current_revision()
    if revision != HEAD_REVISION:
        raise RuntimeError(
            f"Sentinel database revision {revision!r} is unsupported; "
            "back up the database and run 'python -m alembic -c alembic.ini upgrade head'."
        )
