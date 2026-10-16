"""Offline recovery guarantees and adversarial backup tampering tests."""
import hashlib
import hmac
import json
import os
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from sentinel.audit import verify_chain
from sentinel.backup import create_backup, verify_backup, restore_backup
from sentinel.database import migrate
from sentinel.models import AuditRecord
from test_api import AUDIT, client_for, post_event


def ready_db(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    return tmp_path / 'test.db', client, config


def make_backup(tmp_path):
    source, client, config = ready_db(tmp_path)
    # Resolve from settings instead of relying on fixture filename.
    source = __import__('pathlib').Path(config.database_url.removeprefix('sqlite:///'))
    directory = tmp_path / 'backup-one'
    info = create_backup(source, directory, AUDIT)
    return source, directory, info, client


def test_backup_roundtrip_with_incident_integrity(tmp_path):
    source, directory, info, client = make_backup(tmp_path)
    assert info['audit_entries'] >= 1
    assert verify_backup(directory, AUDIT) == info
    restored = tmp_path / 'restored.sqlite3'
    assert restore_backup(directory, restored, AUDIT) == info
    assert restored.read_bytes() == (directory / 'snapshot.sqlite3').read_bytes()
    assert os.name != 'posix' or restored.stat().st_mode & 0o077 == 0
    assert not list(tmp_path.glob('.sentinel-restore-*.tmp'))


def test_online_snapshot_is_consistent_during_later_writes(tmp_path):
    source, directory, info, client = make_backup(tmp_path)
    assert post_event(client).status_code == 202
    assert verify_backup(directory, AUDIT) == info
    assert source.stat().st_size > 0


def test_wrong_audit_key_is_rejected(tmp_path):
    _, directory, _, _ = make_backup(tmp_path)
    with pytest.raises(ValueError, match='authentication'):
        verify_backup(directory, 'y' * 48)


def test_corrupt_snapshot_is_rejected(tmp_path):
    _, directory, _, _ = make_backup(tmp_path)
    with (directory / 'snapshot.sqlite3').open('ab') as out:
        out.write(b'altered')
    with pytest.raises(ValueError, match='checksum'):
        verify_backup(directory, AUDIT)


def test_manifest_tampering_is_rejected(tmp_path):
    _, directory, _, _ = make_backup(tmp_path)
    manifest = directory / 'manifest.json'
    content = json.loads(manifest.read_text())
    content['data']['audit_entries'] = 999
    manifest.write_text(json.dumps(content))
    with pytest.raises(ValueError, match='authentication'):
        verify_backup(directory, AUDIT)


def test_backups_cannot_overwrite_or_restore_existing(tmp_path):
    source, directory, _, _ = make_backup(tmp_path)
    with pytest.raises(FileExistsError):
        create_backup(source, directory, AUDIT)
    with pytest.raises(FileExistsError):
        restore_backup(directory, source, AUDIT)
    assert verify_backup(directory, AUDIT)


def test_recovery_rejects_invalid_source_schema(tmp_path):
    source = tmp_path / 'invalid.db'
    with sqlite3.connect(source) as c:
        c.execute('CREATE TABLE unexpected(a INTEGER)')
    with pytest.raises(RuntimeError, match='revision'):
        create_backup(source, tmp_path / 'bad-backup', AUDIT)
    assert not (tmp_path / 'bad-backup').exists()


def test_recovery_rejects_modified_audit_chain(tmp_path):
    source, directory, _, _ = make_backup(tmp_path)
    with sqlite3.connect(directory / 'snapshot.sqlite3') as c:
        c.execute("UPDATE audit_records SET action='tampered'")
    with pytest.raises(ValueError, match='checksum'):
        verify_backup(directory, AUDIT)
    with pytest.raises(ValueError):
        restore_backup(directory, tmp_path / 'should-not-exist.db', AUDIT)
    assert not (tmp_path / 'should-not-exist.db').exists()


def test_recovery_rejects_symlinked_snapshot(tmp_path):
    _, directory, _, _ = make_backup(tmp_path)
    snapshot = directory / 'snapshot.sqlite3'
    other = tmp_path / 'other-file'
    other.write_bytes(snapshot.read_bytes())
    snapshot.unlink()
    try:
        snapshot.symlink_to(other)
    except OSError:
        pytest.skip('Filesystem does not allow symlinks')
    with pytest.raises(ValueError, match='non-symlink'):
        verify_backup(directory, AUDIT)


def test_backup_directory_private_on_posix(tmp_path):
    _, directory, _, _ = make_backup(tmp_path)
    if os.name == 'posix':
        assert directory.stat().st_mode & 0o077 == 0
        assert (directory/'manifest.json').stat().st_mode & 0o077 == 0
        assert (directory/'snapshot.sqlite3').stat().st_mode & 0o077 == 0


def test_private_destination_parent_required(tmp_path):
    source, _, _, _ = make_backup(tmp_path)
    parent = tmp_path / 'unsafe'
    parent.mkdir()
    if os.name != 'posix':
        pytest.skip('POSIX permission check only')
    parent.chmod(0o777)
    with pytest.raises(ValueError, match='group/world writable'):
        create_backup(source, parent / 'backup', AUDIT)