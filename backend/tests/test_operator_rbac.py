"""Verified per-operator authorization and attribution across real API/database paths."""
import hashlib
import json
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from sentinel.app import create_app
from sentinel.database import migrate
from sentinel.models import AlertDecision, AuditRecord
from sentinel.settings import OperatorIdentity, Settings, load_settings
from test_api import KEY, AUDIT, OP, payload, post_event

TOKENS = {"auditor": secrets.token_urlsafe(48), "analyst.01": secrets.token_urlsafe(48), "chief-admin": secrets.token_urlsafe(48)}
ROLES = {"auditor": "viewer", "analyst.01": "analyst", "chief-admin": "admin"}


def headers(operator_id):
    return {"Authorization": f"Bearer {TOKENS[operator_id]}"}


def configured_client(tmp_path):
    identities = tuple(OperatorIdentity(name, ROLES[name], hashlib.sha256(token.encode()).hexdigest())
                       for name, token in TOKENS.items())
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'rbac.db'}", operator_token=OP,
                        audit_key=AUDIT, sensor_keys={"lab-one": KEY},
                        frontend_origins=("http://localhost:3000",), operators=identities)
    migrate(settings.database_url)
    return TestClient(create_app(settings)), settings


def make_alert(client):
    response = post_event(client, payload(category="endpoint", action="malware_detected", source_ip=None))
    assert response.status_code == 202
    return response.json()["new_alert_ids"][0]


def test_individual_operator_identity_and_legacy_disabled(tmp_path):
    client, _ = configured_client(tmp_path)
    for name, role in ROLES.items():
        response = client.get("/api/v1/session", headers=headers(name))
        assert response.status_code == 200
        assert response.json()["operator_id"] == name
        assert response.json()["role"] == role
        assert "token_sha256" not in response.text
    assert client.get("/api/v1/session", headers={"Authorization": f"Bearer {OP}"}).status_code == 401
    assert client.get("/api/v1/session").status_code == 401
    assert client.get("/api/v1/session", headers={"Authorization": "Bearer 1"}).status_code == 401


def test_viewer_is_read_only_and_cannot_access_audit(tmp_path):
    client, settings = configured_client(tmp_path)
    alert_id = make_alert(client)
    assert client.get("/api/v1/overview", headers=headers("auditor")).status_code == 200
    assert client.get("/api/v1/alerts", headers=headers("auditor")).status_code == 200
    assert client.get(f"/api/v1/alerts/{alert_id}/history", headers=headers("auditor")).status_code == 200
    assert client.get("/api/v1/audit/integrity", headers=headers("auditor")).status_code == 403
    response = client.post(f"/api/v1/alerts/{alert_id}/transition", headers=headers("auditor"),
                           json={"expected_state": "open", "new_state": "investigating",
                                 "reason": "Viewer must not modify security incident."})
    assert response.status_code == 403
    assert client.get("/api/v1/alerts", headers=headers("auditor")).json()[0]["state"] == "open"
    with Session(create_engine(settings.database_url)) as session:
        assert not session.scalars(select(AlertDecision)).all()


def test_analyst_triage_is_attributed_and_admin_audit(tmp_path):
    client, settings = configured_client(tmp_path)
    alert_id = make_alert(client)
    response = client.post(f"/api/v1/alerts/{alert_id}/transition", headers=headers("analyst.01"),
                           json={"expected_state": "open", "new_state": "investigating",
                                 "reason": "Investigated alert and linked evidence."})
    assert response.status_code == 200, response.text
    assert client.get("/api/v1/audit/integrity", headers=headers("analyst.01")).status_code == 403
    check = client.get("/api/v1/audit/integrity", headers=headers("chief-admin"))
    assert check.status_code == 200 and check.json()["valid"] is True
    history = client.get(f"/api/v1/alerts/{alert_id}/history", headers=headers("auditor")).json()
    assert history[0]["actor"] == "analyst.01"
    with Session(create_engine(settings.database_url)) as session:
        events = session.scalars(select(AuditRecord).where(AuditRecord.action == "alert.transition")).all()
        assert len(events) == 1 and events[0].actor == "analyst.01"


def test_load_settings_rejects_invalid_enrollment_and_legacy_fallback(monkeypatch):
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "a" * 48)
    monkeypatch.setenv("SENTINEL_SENSOR_KEYS", json.dumps({"lab-one": "k" * 48}))
    monkeypatch.setenv("SENTINEL_OPERATOR_TOKEN", "o" * 48)
    sample = hashlib.sha256("a-long-private-operator-token".encode()).hexdigest()
    for bad in ("{}", "not-json", json.dumps({"guest": {"role": "owner", "token_sha256": sample}}),
                json.dumps({"guest": {"role": "viewer", "token_sha256": "INVALID"}}),
                json.dumps({"guest": {"role": "viewer", "token_sha256": sample, "extra": 1}}),
                json.dumps({"guest": {"role": "viewer", "token_sha256": sample},
                            "other": {"role": "admin", "token_sha256": sample}})):
        monkeypatch.setenv("SENTINEL_OPERATORS", bad)
        with pytest.raises(RuntimeError):
            load_settings()
    monkeypatch.setenv("SENTINEL_OPERATORS", json.dumps({"analyst.01": {"role": "analyst", "token_sha256": sample}}))
    settings = load_settings()
    assert settings.operators[0].operator_id == "analyst.01"
