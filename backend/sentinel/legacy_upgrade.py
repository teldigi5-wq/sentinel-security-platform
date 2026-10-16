"""One-time, conservative legacy v0.4 SQLite upgrade.

Requires an offline local database, correct audit key, and a separate backup.
Never baseline unknown schemas, forged audits, or already-versioned databases.
"""
from pathlib import Path
import os
import sqlite3
import stat
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session
from .audit import _digest, _time_key, verify_case_decisions
from .database import alembic_config, migrate
from .models import AuditHead, AuditRecord, Base, OperatorCredential


def upgrade_legacy_sqlite(database_path: Path, backup_path: Path, audit_key: str) -> None:
    if database_path.is_symlink():
        raise RuntimeError("Legacy database symlinks are forbidden")
    database_path = database_path.resolve(strict=True)
    backup_path = backup_path.absolute()
    if database_path == backup_path or backup_path.exists():
        raise RuntimeError("Backup path must be new and different from the live database")
    if len(audit_key) < 32 or not database_path.is_file() or database_path.is_symlink():
        raise RuntimeError("Refusing invalid legacy database path or audit key")
    if stat.S_IMODE(database_path.stat().st_mode) & 0o077:
        raise RuntimeError("Legacy database permissions must be private (chmod 600)")
    url = f"sqlite:///{database_path}"
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            existing_tables = set(inspect(conn).get_table_names())
            if "alembic_version" in existing_tables or "audit_heads" in existing_tables or "operator_credentials" in existing_tables:
                raise RuntimeError("Already versioned or unknown Sentinel schema")
            differences = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
            if (len(differences) != 3 or
                {diff[1].name for diff in differences if diff[0] == "add_table"} != {AuditHead.__tablename__, OperatorCredential.__tablename__} or
                {diff[1].name for diff in differences if diff[0] == "add_index"} != {"idx_operator_credentials_operator"}):
                raise RuntimeError("Legacy schema mismatch; refuse to baseline unknown data")
            with Session(bind=conn) as session:
                previous = "0" * 64
                for record in session.scalars(select(AuditRecord).order_by(AuditRecord.id)):
                    expected = _digest(audit_key, _time_key(record.at), record.actor,
                                       record.action, record.resource, previous)
                    if record.previous_hash != previous or record.entry_hash != expected:
                        raise RuntimeError("Legacy audit integrity failed; investigate before migration")
                    previous = record.entry_hash
                if not verify_case_decisions(session):
                    raise RuntimeError("Legacy case history integrity failed")
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        # sqlite3 backup is transactionally consistent; private backup created exclusively.
        fd = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with sqlite3.connect(database_path) as src, sqlite3.connect(backup_path) as dst:
                src.backup(dst)
        except Exception:
            backup_path.unlink(missing_ok=True)
            raise
        command.stamp(alembic_config(url), "0001_initial")
        migrate(url)
    finally:
        engine.dispose()
