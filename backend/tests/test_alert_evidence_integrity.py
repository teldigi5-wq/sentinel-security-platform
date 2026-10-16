"""Alert integrity regression: signed payloads, links and historical limits."""
from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from sentinel.app import create_app
from sentinel.audit import append_audit, verify_alert_evidence, verify_chain
from sentinel.backup import create_backup
from sentinel.models import Alert, AlertEvidence, AuditRecord, SecurityEvent
from test_api import AUDIT, auth, client_for, post_event, payload


def malware(tmp_path):
    client, settings = client_for(tmp_path)
    r = post_event(client, payload(category="endpoint", action="malware_detected", source_ip=None))
    assert r.status_code == 202
    aid = r.json()["new_alert_ids"][0]
    assert client.get("/api/v1/audit/status", headers=auth()).json()["state"] == "anchored"
    return client, settings, aid


@pytest.mark.parametrize("field,new_value", [
    ("severity", "low"),
    ("title", "Downgraded finding"),
    ("rule_id", "unsupported-rule"),
    ("source_ip", "203.0.113.5"),
    ("fingerprint", "forged-fingerprint"),
])
def test_alert_field_tamper_detected_at_runtime_and_startup(tmp_path, field, new_value):
    client, settings, aid = malware(tmp_path)
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        setattr(session.get(Alert, aid), field, new_value)
        session.commit()
        assert verify_chain(session, AUDIT)
        assert not verify_alert_evidence(session)[0]
    engine.dispose()
    assert client.get("/api/v1/audit/status", headers=auth()).json()["state"] == "integrity_failed"
    with pytest.raises(RuntimeError, match="integrity"):
        create_app(settings)


def test_deleted_link_is_detected_and_backup_refused(tmp_path):
    client, settings, aid = malware(tmp_path)
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        session.delete(session.scalar(select(AlertEvidence)))
        session.commit()
        assert verify_chain(session, AUDIT)
        assert not verify_alert_evidence(session)[0]
    engine.dispose()
    assert not client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"]
    with pytest.raises(ValueError, match="integrity"):
        create_backup(tmp_path / "test.db", tmp_path / "backup", AUDIT)


def test_unaudited_link_is_detected_even_with_updated_count(tmp_path):
    client, settings, aid = malware(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        event = next(x for x in session.scalars(select(SecurityEvent)) if x.category == "authentication")
        session.add(AlertEvidence(alert_id=aid, event_id=event.id))
        session.get(Alert, aid).evidence_count += 1
        session.commit()
        assert verify_chain(session, AUDIT)
        assert not verify_alert_evidence(session)[0]
    engine.dispose()


def test_existing_alert_gets_signed_new_links(tmp_path):
    client, settings = client_for(tmp_path)
    for _ in range(7):
        assert post_event(client).status_code == 202
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        alert = session.scalar(select(Alert))
        assert alert.evidence_count == 7
        links = session.scalars(select(AuditRecord).where(
            AuditRecord.action == "alert.evidence.linked")).all()
        assert len(links) == 7
        assert verify_alert_evidence(session) == (True, 0)
    engine.dispose()


def test_legacy_alerts_and_links_are_partially_verifiable(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        event = session.scalar(select(SecurityEvent))
        aid = str(uuid.uuid4())
        session.add(Alert(id=aid, rule_id="legacy-v1", fingerprint="old-rule",
                          severity="medium", title="Historical alert",
                          explanation="Unanchored historical alert",
                          asset_id=event.asset_id, source_ip=event.source_ip,
                          evidence_count=1, created_at=datetime.now(timezone.utc)))
        session.add(AlertEvidence(alert_id=aid, event_id=event.id))
        append_audit(session, AUDIT, actor="detection-engine",
                     action="alert.created", resource=aid)
        session.commit()
        assert verify_alert_evidence(session) == (True, 2)
    engine.dispose()
    status = client.get("/api/v1/audit/integrity", headers=auth()).json()
    assert status["valid"] is True
    assert status["legacy_unanchored_alert_records"] == 2
    assert status["event_payload_assurance"] == "partial_legacy"
    assert client.get("/api/v1/audit/status", headers=auth()).json()["state"] == "partial_legacy"


def test_triage_does_not_break_anchored_alert(tmp_path):
    client, settings, aid = malware(tmp_path)
    result = client.post(f"/api/v1/alerts/{aid}/transition", headers=auth(), json={
        "expected_state": "open", "new_state": "investigating", "reason": "verified triage"})
    assert result.status_code == 200
    assert client.get("/api/v1/audit/status", headers=auth()).json()["state"] == "anchored"
