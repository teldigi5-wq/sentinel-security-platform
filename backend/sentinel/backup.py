"""Offline restore and SQLite online snapshot backup with independent integrity checks.

This is a local maintenance utility, not an HTTP API or production backup service.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
from urllib.parse import quote

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .audit import verify_case_decisions, verify_chain, verify_event_evidence
from .database import HEAD_REVISION, verify_schema
from alembic.migration import MigrationContext
from .models import AuditHead

MANIFEST = 'manifest.json'
SNAPSHOT = 'snapshot.sqlite3'
FORMAT = 'sentinel-sqlite-backup-v1'
CHUNK = 1024 * 1024


def _regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular, non-symlink file')


def _private_parent(parent: Path) -> None:
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError('Destination parent must be a real directory')
    if os.name == 'posix' and parent.stat().st_mode & 0o022:
        raise ValueError('Destination parent must not be group/world writable')


def _sync_directory(path: Path) -> None:
    # Persist newly created directory entries on POSIX filesystems that support it.
    if os.name == 'posix':
        flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as file:
        while block := file.read(CHUNK):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _sign(fields: dict, key: str) -> str:
    return hmac.new(key.encode('utf-8'), _canonical(fields), hashlib.sha256).hexdigest()


def _verified_snapshot(path: Path, audit_key: str, *, revision: str = HEAD_REVISION) -> dict:
    """Validate the *copied* state, never trust an unverified source snapshot."""
    _regular_file(path)
    uri = f'file:{quote(str(path.absolute()), safe="/")}?mode=ro'
    with sqlite3.connect(uri, uri=True) as conn:
        if conn.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise ValueError('SQLite integrity check failed')
    engine = create_engine(f'sqlite:///{path}')
    try:
        if revision == HEAD_REVISION:
            verify_schema(engine)
        elif revision == "0002_audit_head":
            # Support recovery of previously authenticated v0.6 backups.
            # An offline migration is mandatory before API startup.
            with engine.connect() as connection:
                observed_revision = MigrationContext.configure(connection).get_current_revision()
            if observed_revision != revision:
                raise ValueError("Backup revision does not match its snapshot")
        else:
            raise ValueError("Unsupported snapshot database revision")
        with Session(engine) as session:
            # New-format persisted event fields are also sealed into the audit
            # chain; reject tampered snapshots before exporting/restoring them.
            event_valid, _legacy_events = verify_event_evidence(session)
            if not verify_chain(session, audit_key) or not verify_case_decisions(session) or not event_valid:
                raise ValueError('Sentinel audit integrity verification failed')
            head = session.get(AuditHead, 1)
            if head is None:
                raise ValueError('Missing audit head')
            return {'audit_entries': head.entry_count, 'audit_head': head.last_hash}
    finally:
        engine.dispose()


def _private_write(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def create_backup(source: Path, destination: Path, audit_key: str) -> dict:
    """Create a private new backup directory. Never replace an existing backup."""
    if len(audit_key) < 32:
        raise ValueError('A strong audit key is required')
    source, destination = Path(source), Path(destination)
    _regular_file(source)
    _private_parent(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Backup destination already exists')
    destination.mkdir(mode=0o700)
    snapshot = destination / SNAPSHOT
    try:
        # SQLite's backup API includes a transactionally consistent view of WAL data.
        uri = f'file:{quote(str(source.absolute()), safe="/")}?mode=ro'
        with sqlite3.connect(uri, uri=True) as origin:
            with sqlite3.connect(str(snapshot)) as target:
                origin.backup(target)
        if os.name == 'posix':
            snapshot.chmod(0o600)
        with snapshot.open('rb') as durable_copy:
            os.fsync(durable_copy.fileno())
        result = _verified_snapshot(snapshot, audit_key)
        data = {
            'format': FORMAT,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'database_sha256': _hash_file(snapshot),
            'schema_revision': HEAD_REVISION,
            **result,
        }
        _private_write(destination / MANIFEST, _canonical({'data': data, 'hmac_sha256': _sign(data, audit_key)}) + b'\n')
        _sync_directory(destination)
        _sync_directory(destination.parent)
        return data
    except BaseException:
        # Directory was newly created and is private. Clean only known new files.
        for name in (MANIFEST, SNAPSHOT):
            (destination / name).unlink(missing_ok=True)
        destination.rmdir()
        raise


def verify_backup(directory: Path, audit_key: str) -> dict:
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Backup must be a real directory')
    if os.name == 'posix' and directory.stat().st_mode & 0o077:
        raise ValueError('Backup directory must be private')
    manifest, snapshot = directory / MANIFEST, directory / SNAPSHOT
    _regular_file(manifest)
    _regular_file(snapshot)
    if manifest.stat().st_size > 8192:
        raise ValueError('Manifest too large')
    try:
        parsed = json.loads(manifest.read_text(encoding='ascii'))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Invalid backup manifest') from exc
    if not isinstance(parsed, dict) or set(parsed) != {'data', 'hmac_sha256'}:
        raise ValueError('Invalid manifest shape')
    data, signature = parsed['data'], parsed['hmac_sha256']
    fields = {'format', 'created_at', 'database_sha256', 'schema_revision', 'audit_entries', 'audit_head'}
    if not isinstance(data, dict) or set(data) != fields or not isinstance(signature, str):
        raise ValueError('Invalid manifest fields')
    if not hmac.compare_digest(_sign(data, audit_key), signature):
        raise ValueError('Manifest authentication failed')
    if data['format'] != FORMAT or data['schema_revision'] not in (HEAD_REVISION, '0002_audit_head'):
        raise ValueError('Unsupported backup format or schema')
    if not hmac.compare_digest(data['database_sha256'], _hash_file(snapshot)):
        raise ValueError('Backup checksum mismatch')
    observed = _verified_snapshot(snapshot, audit_key, revision=data['schema_revision'])
    if observed != {k: data[k] for k in ('audit_entries', 'audit_head')}:
        raise ValueError('Audit head mismatch')
    return data


def restore_backup(directory: Path, destination: Path, audit_key: str) -> dict:
    """Restore to a *new* file only, while the Sentinel API is stopped.

    Existing files are never replaced; caller must verify the API is offline.
    """
    destination = Path(destination)
    _private_parent(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Restore target exists; refusing overwrite')
    data = verify_backup(directory, audit_key)
    temp = destination.parent / f'.sentinel-restore-{secrets.token_hex(12)}.tmp'
    try:
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(temp, flags, 0o600)
        with os.fdopen(fd, 'wb') as out, (Path(directory) / SNAPSHOT).open('rb') as source:
            shutil.copyfileobj(source, out, CHUNK)
            out.flush()
            os.fsync(out.fileno())
        if not hmac.compare_digest(_hash_file(temp), data['database_sha256']):
            raise ValueError('Restore copy checksum mismatch')
        _verified_snapshot(temp, audit_key, revision=data['schema_revision'])
        # Atomic no-replace publication; fail closed on filesystems without hard-link support.
        os.link(temp, destination, follow_symlinks=False)
        _sync_directory(destination.parent)
        return data
    finally:
        temp.unlink(missing_ok=True)
