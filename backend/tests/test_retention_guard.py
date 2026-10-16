"""Retention can remove only expired replay nonces after a verified backup."""
from datetime import timedelta
import os

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from sentinel.audit import verify_chain, verify_case_decisions
from sentinel.backup import verify_backup
from sentinel.database import migrate
from sentinel.models import AuditRecord, AlertEvidence, SecurityEvent, SensorNonce, utcnow
from sentinel.retention import nonce_retention
from sentinel.settings import Settings
from sentinel.app import create_app
from test_api import AUDIT, KEY, OP, post_event


def prepared(tmp_path):
    source = tmp_path / 'sentinel.db'
    url = f'sqlite:///{source}'
    migrate(url)
    settings = Settings(database_url=url, operator_token=OP, audit_key=AUDIT,
                        sensor_keys={'lab-one': KEY}, frontend_origins=('http://localhost:3000',))
    with TestClient(create_app(settings)) as client:
        assert post_event(client).status_code == 202
        engine = create_engine(url)
        with Session(engine) as session:
            nonces = session.scalars(select(SensorNonce)).all()
            assert len(nonces) == 1
            nonce = nonces[0]
            nonce.seen_at = utcnow() - timedelta(days=10)
            session.commit()
        engine.dispose()
    return source


def counts(source):
    engine = create_engine(f'sqlite:///{source}')
    try:
        with Session(engine) as session:
            return tuple(session.scalar(select(func.count()).select_from(model)) for model in
                         (SensorNonce, SecurityEvent, AlertEvidence, AuditRecord))
    finally:
        engine.dispose()


def test_preview_is_non_destructive_and_preserves_evidence(tmp_path):
    source = prepared(tmp_path)
    before = counts(source)
    result = nonce_retention(source, AUDIT, days=7)
    assert result['mode'] == 'preview'
    assert result['eligible_nonces'] == 1
    assert not result['changed']
    assert counts(source) == before


def test_apply_requires_backup_and_preserves_event_audit(tmp_path):
    source = prepared(tmp_path)
    previous = counts(source)
    backup = tmp_path/'before-retention'
    output = nonce_retention(source, AUDIT, apply=True, backup_dir=backup)
    assert output['deleted_nonces'] == 1 and output['changed']
    assert backup.is_dir()
    assert verify_backup(backup, AUDIT)['audit_entries'] == previous[-1]
    after = counts(source)
    assert after[0] == 0
    assert after[1:3] == previous[1:3]
    assert after[3] == previous[3] + 1
    engine = create_engine(f'sqlite:///{source}')
    with Session(engine) as session:
        assert verify_chain(session, AUDIT) and verify_case_decisions(session)
        assert session.scalar(select(AuditRecord).order_by(AuditRecord.id.desc())).action == 'replay-nonces.pruned'
    engine.dispose()
    # No second backup or audit records for an empty retention run.
    assert nonce_retention(source, AUDIT, apply=True, backup_dir=tmp_path/'unused')['changed'] is False
    assert not (tmp_path/'unused').exists()


def test_wrong_key_or_existing_backup_never_removes_nonces(tmp_path):
    source = prepared(tmp_path)
    with pytest.raises(ValueError, match='verification failed'):
        nonce_retention(source, 'W' * 64, apply=True, backup_dir=tmp_path/'bad')
    with pytest.raises(ValueError, match='requires a new verified backup'):
        nonce_retention(source, AUDIT, apply=True)
    backup = tmp_path/'existing'
    backup.mkdir()
    with pytest.raises(FileExistsError):
        nonce_retention(source, AUDIT, apply=True, backup_dir=backup)
    assert counts(source)[0] == 1


def test_tampered_audit_refuses_even_preview(tmp_path):
    source = prepared(tmp_path)
    engine = create_engine(f'sqlite:///{source}')
    with Session(engine) as session:
        audit = session.scalar(select(AuditRecord))
        audit.action = 'altered'
        session.commit()
    engine.dispose()
    with pytest.raises(ValueError, match='verification failed'):
        nonce_retention(source, AUDIT, days=7)
    assert counts(source)[0] == 1


def test_reject_invalid_days_and_unsafe_sources(tmp_path):
    source = prepared(tmp_path)
    for days in (0, -1, 366, True, 7.5):
        with pytest.raises(ValueError, match='days'):
            nonce_retention(source, AUDIT, days=days)
    link = tmp_path / 'linked.sqlite'
    link.symlink_to(source)
    with pytest.raises(ValueError, match='not a symlink'):
        nonce_retention(link, AUDIT)
    with pytest.raises(ValueError, match='regular SQLite'):
        nonce_retention(tmp_path / 'absent.db', AUDIT)


def test_backup_race_abort_keeps_nonces(tmp_path, monkeypatch):
    source = prepared(tmp_path)
    from sentinel import retention
    original = retention.create_backup
    def moved_after_snapshot(source_path, dest, key):
        result = original(source_path, dest, key)
        engine = create_engine(f'sqlite:///{source_path}')
        from sentinel.audit import append_audit, lock_audit_head
        with Session(engine) as session:
            lock_audit_head(session)
            append_audit(session, key, actor='test', action='test.concurrent', resource='fixture')
            session.commit()
        engine.dispose()
        return result
    monkeypatch.setattr(retention, 'create_backup', moved_after_snapshot)
    with pytest.raises(ValueError, match='changed'):
        nonce_retention(source, AUDIT, apply=True, backup_dir=tmp_path/'snapshot')
    assert counts(source)[0] == 1


def test_new_nonce_stays_and_old_is_deleted(tmp_path):
    source = prepared(tmp_path)
    engine = create_engine(f'sqlite:///{source}')
    with Session(engine) as session:
        session.add(SensorNonce(sensor_id='lab-one', nonce='b' * 32, seen_at=utcnow()))
        session.commit()
    engine.dispose()
    out = nonce_retention(source, AUDIT, apply=True, backup_dir=tmp_path/'snapshot')
    assert out['deleted_nonces'] == 1
    assert counts(source)[0] == 1
