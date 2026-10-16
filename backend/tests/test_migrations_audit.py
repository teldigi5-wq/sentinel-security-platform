"""Database revision gates, legacy preservation and multiwriter audit integrity."""
import os
import uuid
import hmac
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import MetaData, create_engine, select, func, text
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient
from sentinel.app import create_app
from sentinel.audit import _digest, _time_key, verify_chain
from sentinel.database import migrate, verify_schema
from sentinel.legacy_upgrade import upgrade_legacy_sqlite
from sentinel.models import Base, AuditHead, AuditRecord, Alert, SecurityEvent
from sentinel.settings import Settings
from test_api import KEY, OP, AUDIT, auth, payload, post_event, client_for


def settings_for(url):
    return Settings(database_url=url, operator_token=OP, audit_key=AUDIT,
                    sensor_keys={"lab-one":KEY}, frontend_origins=("http://localhost:3000",))


def test_app_refuses_unversioned_database(tmp_path):
    url = f"sqlite:///{tmp_path/'unversioned.db'}"
    with pytest.raises(RuntimeError, match="revision"):
        create_app(settings_for(url))
    engine = create_engine(url)
    try:
        assert "security_events" not in __import__("sqlalchemy").inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_explicit_migration_is_idempotent_and_operational(tmp_path):
    url = f"sqlite:///{tmp_path/'fresh.db'}"
    migrate(url)
    migrate(url)
    engine = create_engine(url)
    try:
        verify_schema(engine)
        with Session(engine) as s:
            head=s.get(AuditHead,1)
            assert head.last_hash == "0"*64 and head.entry_count == 0
    finally:
        engine.dispose()
    client = TestClient(create_app(settings_for(url)))
    assert post_event(client).status_code == 202
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"] is True


def test_head_detects_tail_deletion(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(config.database_url)
    with Session(engine) as s:
        last = s.scalar(select(AuditRecord).order_by(AuditRecord.id.desc()).limit(1))
        s.delete(last)
        s.commit()
    engine.dispose()
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"] is False


def test_head_detects_replacement(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(config.database_url)
    with Session(engine) as s:
        head = s.get(AuditHead, 1)
        head.entry_count = 20
        s.commit()
    engine.dispose()
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"] is False


def make_legacy(path):
    engine = create_engine(f"sqlite:///{path}")
    metadata = MetaData()
    for name, table in Base.metadata.tables.items():
        if name not in ("audit_heads", "operator_credentials", "sensor_status"):
            table.to_metadata(metadata)
    metadata.create_all(engine)
    with Session(engine) as s:
        at = datetime.now(timezone.utc)
        resource = "legacy-event-id"
        # Older authentic records used an ID-only event audit resource; a
        # corresponding stored event must exist for restart certification.
        s.add(SecurityEvent(id=resource, sensor_id="lab-one", asset_id="workstation-1",
                            category="authentication", action="auth_success",
                            source_ip="192.0.2.11", observed_at=at))
        digest = _digest(AUDIT, _time_key(at), "sensor:lab-one", "event.ingested", resource, "0"*64)
        s.add(AuditRecord(at=at, actor="sensor:lab-one", action="event.ingested",
                          resource=resource, previous_hash="0"*64, entry_hash=digest))
        s.commit()
    engine.dispose()
    os.chmod(path, 0o600)


def test_guarded_legacy_preserves_original_audit_and_backup(tmp_path):
    path=tmp_path/'v04.db'
    backup=tmp_path/'secured-copy.db'
    make_legacy(path)
    upgrade_legacy_sqlite(path, backup, AUDIT)
    assert backup.exists() and backup.stat().st_mode & 0o077 == 0
    engine = create_engine(f"sqlite:///{path}")
    with Session(engine) as s:
        assert s.get(AuditHead,1).entry_count == 1
        assert verify_chain(s,AUDIT)
    engine.dispose()
    assert post_event(TestClient(create_app(settings_for(f'sqlite:///{path}')))).status_code == 202


def test_guarded_legacy_refuses_wrong_audit_key_without_backup(tmp_path):
    path=tmp_path/'v04.db'
    backup=tmp_path/'backup.db'
    make_legacy(path)
    with pytest.raises(RuntimeError, match="audit integrity"):
        upgrade_legacy_sqlite(path, backup, "x"*48)
    assert not backup.exists()


def test_guarded_legacy_refuses_schema_drift(tmp_path):
    path=tmp_path/'v04.db';backup=tmp_path/'backup.db'
    make_legacy(path)
    engine=create_engine(f"sqlite:///{path}")
    with engine.begin() as c:
        c.execute(text("ALTER TABLE alerts ADD COLUMN unaudited_data TEXT"))
    engine.dispose()
    with pytest.raises(RuntimeError, match="schema mismatch"):
        upgrade_legacy_sqlite(path, backup, AUDIT)
    assert not backup.exists()


def test_sqlite_concurrent_ingest_writers_have_linear_audit(tmp_path):
    client, config = client_for(tmp_path)
    def one(_):
        return post_event(client).status_code
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses=list(pool.map(one,range(8)))
    assert statuses==[202]*8
    audit=client.get("/api/v1/audit/integrity", headers=auth()).json()
    assert audit["valid"] and audit["records"] == 9
    assert len(client.get("/api/v1/alerts",headers=auth()).json()) == 1
    engine=create_engine(config.database_url)
    with Session(engine) as s:
        assert s.scalar(select(func.count()).select_from(AuditRecord)) == s.get(AuditHead,1).entry_count
    engine.dispose()
