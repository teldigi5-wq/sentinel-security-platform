"""Start-up should fail closed if persisted security evidence is compromised."""
from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from sentinel.app import create_app
from sentinel.audit import append_audit
from sentinel.models import AlertDecision, AuditRecord, SecurityEvent
from test_api import AUDIT, auth, client_for, post_event


def test_pristine_and_anchored_databases_restart(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    rebooted = create_app(settings)
    from fastapi.testclient import TestClient
    assert TestClient(rebooted).get('/api/v1/events', headers=auth()).status_code == 200


def test_tampered_event_prevents_api_startup(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        event = session.scalar(select(SecurityEvent))
        event.source_ip = '192.0.2.129'
        session.commit()
    engine.dispose()
    with pytest.raises(RuntimeError, match='integrity check failed at startup'):
        create_app(settings)


def test_tampered_audit_chain_prevents_api_startup(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        record = session.scalar(select(AuditRecord))
        record.actor = 'compromised-actor'
        session.commit()
    engine.dispose()
    with pytest.raises(RuntimeError, match='integrity check failed at startup'):
        create_app(settings)


def test_legacy_unanchored_record_remains_compatible_and_labeled(tmp_path):
    client, settings = client_for(tmp_path)
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        event = SecurityEvent(id=str(uuid.uuid4()), sensor_id='lab-one', asset_id='workstation-1',
                              category='authentication', action='auth_success', source_ip=None,
                              observed_at=datetime.now(timezone.utc))
        session.add(event)
        session.flush()
        append_audit(session, AUDIT, actor='sensor:lab-one',
                     action='event.ingested', resource=event.id)
        session.commit()
    engine.dispose()
    from fastapi.testclient import TestClient
    response = TestClient(create_app(settings)).get('/api/v1/audit/integrity', headers=auth())
    assert response.status_code == 200
    assert response.json()['event_payload_assurance'] == 'partial_legacy'


def test_alert_decision_tamper_prevents_restart(tmp_path):
    client, settings = client_for(tmp_path)
    r = post_event(client, raw=__import__('test_api').payload(
        category='endpoint', action='malware_detected', source_ip=None))
    alert_id = r.json()['new_alert_ids'][0]
    assert client.post(f'/api/v1/alerts/{alert_id}/transition', headers=auth(), json={
        'expected_state': 'open', 'new_state': 'investigating',
        'reason': 'Validated investigation through authorized lab telemetry.'}).status_code == 200
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        decision = session.scalar(select(AlertDecision))
        decision.reason = 'unauthorized edit'
        session.commit()
    engine.dispose()
    with pytest.raises(RuntimeError, match='integrity check failed at startup'):
        create_app(settings)
