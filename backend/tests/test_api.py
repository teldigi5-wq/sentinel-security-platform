import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sentinel.app import create_app
from sentinel.models import AuditRecord
from sentinel.settings import Settings


OP = "o" * 48
KEY = "k" * 48
AUDIT = "a" * 48


def client_for(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}", operator_token=OP,
                        audit_key=AUDIT, sensor_keys={"lab-one": KEY}, frontend_origins=("http://localhost:3000",))
    return TestClient(create_app(settings)), settings


def payload(**overrides):
    data = {"asset_id": "workstation-1", "category": "authentication", "action": "auth_failure",
            "source_ip": "198.51.100.42", "observed_at": datetime.now(timezone.utc).isoformat()}
    data.update(overrides)
    return json.dumps(data, separators=(",", ":")).encode()


def post_event(client, raw=None, nonce=None, signature=None, stamp=None, sensor="lab-one"):
    raw = raw if raw is not None else payload()
    nonce = nonce or secrets.token_hex(16)
    stamp = stamp or str(int(time.time()))
    canonical = f"{sensor}\n{stamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
    signature = signature or hmac.new(KEY.encode(), canonical, hashlib.sha256).hexdigest()
    return client.post("/api/v1/events", content=raw, headers={
        "X-Sentinel-Sensor": sensor, "X-Sentinel-Timestamp": stamp,
        "X-Sentinel-Nonce": nonce, "X-Sentinel-Signature": signature})


def auth():
    return {"Authorization": f"Bearer {OP}"}


def test_health_readonly_access_and_no_store(tmp_path):
    client, _ = client_for(tmp_path)
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/overview").status_code == 401
    assert client.get("/api/v1/overview", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = client.get("/api/v1/overview", headers=auth())
    assert r.status_code == 200
    assert r.json()["events"] == 0
    assert r.headers["cache-control"] == "no-store"
    assert r.json()["defensive_enforcement"] == "not-installed"


def test_auth_burst_creates_real_alert_and_evidence(tmp_path):
    client, _ = client_for(tmp_path)
    for i in range(4):
        result = post_event(client)
        assert result.status_code == 202, result.text
        assert result.json()["new_alert_ids"] == []
    fifth = post_event(client)
    assert fifth.status_code == 202
    assert len(fifth.json()["new_alert_ids"]) == 1
    alerts = client.get("/api/v1/alerts", headers=auth()).json()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["evidence_count"] == 5
    evidence = client.get(f"/api/v1/alerts/{alerts[0]['id']}/evidence", headers=auth()).json()
    assert len(evidence) == 5
    overview = client.get("/api/v1/overview", headers=auth()).json()
    assert overview["assets"] == 1 and overview["events"] == 5 and overview["alerts"] == 1
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"] is True


def test_malware_is_reported_not_executed(tmp_path):
    client, _ = client_for(tmp_path)
    raw = payload(category="endpoint", action="malware_detected", source_ip=None)
    result = post_event(client, raw)
    assert result.status_code == 202
    alerts = client.get("/api/v1/alerts", headers=auth()).json()
    assert alerts[0]["severity"] == "high" and alerts[0]["rule_id"] == "malware-indicator-v1"


def test_bad_signatures_expired_and_replay_are_rejected(tmp_path):
    client, _ = client_for(tmp_path)
    assert post_event(client, signature="0" * 64).status_code == 401
    assert post_event(client, stamp=str(int(time.time()) - 1000)).status_code == 401
    nonce = secrets.token_hex(16)
    assert post_event(client, nonce=nonce).status_code == 202
    assert post_event(client, nonce=nonce).status_code == 409
    assert client.get("/api/v1/overview", headers=auth()).json()["events"] == 1


def test_invalid_ip_action_timestamp_and_large_payload(tmp_path):
    client, _ = client_for(tmp_path)
    assert post_event(client, payload(source_ip="not-an-ip")).status_code == 422
    assert post_event(client, payload(category="network", action="auth_failure")).status_code == 422
    assert post_event(client, payload(observed_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())).status_code == 422
    assert post_event(client, b"x" * 9000).status_code == 413


def test_tampering_breaks_audit_integrity(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"]
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        row = session.scalars(select(AuditRecord)).first()
        row.resource = "modified-evidence-id"
        session.commit()
    assert not client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"]


def test_isolated_sources_do_not_trigger_shared_burst(tmp_path):
    client, _ = client_for(tmp_path)
    for i in range(4):
        assert post_event(client, payload(source_ip=f"192.0.2.{i+1}")).status_code == 202
    assert post_event(client, payload(source_ip="192.0.2.10")).status_code == 202
    assert client.get("/api/v1/alerts", headers=auth()).json() == []


def test_untrusted_extra_fields_are_rejected(tmp_path):
    client, _ = client_for(tmp_path)
    assert post_event(client, payload(command="block-all-network")).status_code == 422


def test_cors_restricted_to_local_dashboard(tmp_path):
    client, _ = client_for(tmp_path)
    allowed = client.get("/api/v1/health", headers={"Origin": "http://localhost:3000"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    forbidden = client.get("/api/v1/health", headers={"Origin": "https://evil.invalid"})
    assert forbidden.headers.get("access-control-allow-origin") is None


def test_network_denial_burst_alert(tmp_path):
    client, _ = client_for(tmp_path)
    for _ in range(12):
        r = post_event(client, payload(category="network", action="network_denied"))
        assert r.status_code == 202, r.text
    alerts = client.get("/api/v1/alerts", headers=auth()).json()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "network-denial-burst-v1"
    assert alerts[0]["evidence_count"] == 12


def test_operator_api_never_accepts_sensor_secret(tmp_path):
    client, _ = client_for(tmp_path)
    response = client.get("/api/v1/events", headers={"Authorization": f"Bearer {KEY}"})
    assert response.status_code == 401


def test_utc_timestamp_response_explicitly_offset_aware(tmp_path):
    client, _ = client_for(tmp_path)
    assert post_event(client).status_code == 202
    latest = client.get("/api/v1/events", headers=auth()).json()[0]
    assert latest["observed_at"].endswith("+00:00")


def test_missing_sensor_cannot_ingest(tmp_path):
    client, _ = client_for(tmp_path)
    assert post_event(client, sensor="unknown-sensor").status_code == 401
