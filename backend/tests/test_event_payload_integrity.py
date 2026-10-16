"""v0.22: signed event evidence must bind persisted contents, not only IDs."""
from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from sentinel.audit import append_audit, verify_chain, verify_event_evidence
from sentinel.backup import create_backup
from sentinel.models import SecurityEvent, AuditRecord
from sentinel.retention import nonce_retention
from test_api import AUDIT, client_for, post_event, auth, payload


def _tamper(url, **changes):
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            event = session.scalar(select(SecurityEvent))
            assert event is not None
            for name, value in changes.items():
                setattr(event, name, value)
            session.commit()
            # Demonstrate the original vulnerability: chain HMAC remains valid.
            assert verify_chain(session, AUDIT)
    finally:
        engine.dispose()


def test_event_anchor_contains_digest_and_detects_source_ip_tamper(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    before = client.get('/api/v1/audit/integrity', headers=auth()).json()
    assert before['valid'] is True
    assert before['legacy_unanchored_events'] == 0
    assert before['event_payload_assurance'] == 'anchored'
    _tamper(config.database_url, source_ip='198.51.100.99')
    after = client.get('/api/v1/audit/integrity', headers=auth()).json()
    assert after['valid'] is False
    assert after['event_payload_assurance'] == 'integrity_failed'


@pytest.mark.parametrize('changes', [
    {'action': 'auth_success'},
    {'asset_id': 'other-host'},
    {'category': 'endpoint'},
    {'sensor_id': 'other-sensor'},
])
def test_event_tampering_invalidates_integrity(tmp_path, changes):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    _tamper(config.database_url, **changes)
    assert client.get('/api/v1/audit/integrity', headers=auth()).json()['valid'] is False


def test_missing_event_is_detected_even_when_audit_chain_is_intact(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(config.database_url)
    try:
        with Session(engine) as session:
            row = session.scalar(select(SecurityEvent))
            session.delete(row)
            session.commit()
            assert verify_chain(session, AUDIT)
    finally:
        engine.dispose()
    assert client.get('/api/v1/audit/integrity', headers=auth()).json()['valid'] is False


def test_legacy_id_only_resource_is_explicitly_unverifiable(tmp_path):
    client, config = client_for(tmp_path)
    engine = create_engine(config.database_url)
    try:
        with Session(engine) as session:
            event = SecurityEvent(id=str(uuid.uuid4()), sensor_id='lab-one', asset_id='workstation-1',
                                  category='authentication', action='auth_success', source_ip=None,
                                  observed_at=datetime.now(timezone.utc))
            session.add(event)
            session.flush()
            append_audit(session, AUDIT, actor='sensor:lab-one',
                         action='event.ingested', resource=event.id)  # pre-v0.22 format
            session.commit()
            valid, legacy_count = verify_event_evidence(session)
            assert valid and legacy_count == 1
    finally:
        engine.dispose()
    response = client.get('/api/v1/audit/integrity', headers=auth()).json()
    assert response['valid'] is True  # authentic audit record, NOT an authenticated event payload
    assert response['event_payload_assurance'] == 'partial_legacy'
    assert response['legacy_unanchored_events'] == 1


def test_backup_refuses_event_payload_tamper(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    _tamper(config.database_url, action='auth_success')
    with pytest.raises(ValueError, match='audit integrity'):
        create_backup(tmp_path/'test.db', tmp_path/'evidence-backup', AUDIT)


def test_retention_refuses_event_payload_tamper(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    _tamper(config.database_url, action='auth_success')
    with pytest.raises((RuntimeError, ValueError), match='verification failed'):
        nonce_retention(tmp_path/'test.db', AUDIT)


def test_multi_event_new_records_have_unique_anchors(tmp_path):
    client, config = client_for(tmp_path)
    assert post_event(client).status_code == 202
    assert post_event(client).status_code == 202
    engine = create_engine(config.database_url)
    try:
        with Session(engine) as session:
            anchors = session.scalars(select(AuditRecord.resource).where(
                AuditRecord.action == 'event.ingested')).all()
            assert len(anchors) == 2
            assert all(a.startswith('event:v1:') and len(a) == 110 for a in anchors)
            assert len(set(anchors)) == 2
    finally:
        engine.dispose()
