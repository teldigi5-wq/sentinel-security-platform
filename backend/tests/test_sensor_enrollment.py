"""Security regression tests for pinned sensor-to-asset identity."""
import json
import secrets
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from sentinel.app import create_app
from sentinel.database import migrate
from sentinel.models import SecurityEvent, SensorNonce, SensorStatus, AuditRecord
from sentinel.settings import Settings, load_settings
from test_api import OP, AUDIT, KEY, payload, post_event, auth, client_for
from test_sensor_health import beat

def enrolled_client(tmp_path, asset="workstation-1"):
    cfg=Settings(database_url=f"sqlite:///{tmp_path/'enrolled.db'}",
                 operator_token=OP, sensor_keys={"lab-one": KEY}, audit_key=AUDIT,
                 frontend_origins=("http://localhost:3000",),
                 sensor_assets={"lab-one": asset})
    migrate(cfg.database_url)
    return TestClient(create_app(cfg)), cfg

def coverage(client):
    response=client.get("/api/v1/sensors",headers=auth())
    assert response.status_code==200
    return response.json()

def test_expected_asset_does_not_claim_unseen_contact(tmp_path):
    client,_=enrolled_client(tmp_path)
    data=coverage(client)
    assert data["sensors"][0]["status"]=="never_seen"
    assert data["sensors"][0]["asset_id"] is None
    assert data["sensors"][0]["expected_asset_id"]=="workstation-1"
    assert data["sensors"][0]["binding_mode"]=="explicit"
    assert data["summary"]=={"configured":1,"healthy":0,"gaps":1,"explicitly_enrolled":1}

def test_signed_impersonation_rejected_without_transaction_side_effects(tmp_path):
    client,cfg=enrolled_client(tmp_path)
    assert post_event(client,payload(asset_id="other-server")).status_code==403
    assert beat(client,body=b'{"asset_id":"other-server"}').status_code==403
    assert coverage(client)["sensors"][0]["status"]=="never_seen"
    engine=create_engine(cfg.database_url)
    with Session(engine) as session:
        for model in (SecurityEvent,SensorNonce,AuditRecord,SensorStatus):
            assert session.scalar(select(func.count()).select_from(model))==0
    engine.dispose()
    assert client.get("/api/v1/audit/integrity",headers=auth()).json()["valid"] is True

def test_signed_contact_for_approved_asset_counts(tmp_path):
    client,_=enrolled_client(tmp_path)
    assert beat(client).status_code==202
    assert post_event(client).status_code==202
    data=coverage(client)
    assert data["summary"]=={"configured":1,"healthy":1,"gaps":0,"explicitly_enrolled":1}
    assert data["sensors"][0]["heartbeat_count"]==1
    assert data["sensors"][0]["event_count"]==1

def test_first_contact_is_immutable_but_not_administrative_enrollment(tmp_path):
    client,_=client_for(tmp_path)
    assert beat(client).status_code==202
    assert post_event(client,payload(asset_id="new-server")).status_code==403
    assert beat(client,body=b'{"asset_id":"new-server"}').status_code==403
    status=coverage(client)["sensors"][0]
    assert status["binding_mode"]=="first_contact"
    assert status["asset_id"]=="workstation-1"
    assert coverage(client)["summary"]["explicitly_enrolled"]==0

def test_rejected_identity_does_not_burn_nonce(tmp_path):
    client,_=enrolled_client(tmp_path)
    nonce=secrets.token_hex(16)
    assert post_event(client,payload(asset_id="wrong-asset"),nonce=nonce).status_code==403
    assert post_event(client,payload(),nonce=nonce).status_code==202
    assert post_event(client,payload(),nonce=nonce).status_code==409

def test_environment_enrollment_requires_complete_valid_mapping(monkeypatch):
    monkeypatch.setenv("SENTINEL_OPERATOR_TOKEN",OP)
    monkeypatch.setenv("SENTINEL_AUDIT_KEY",AUDIT)
    monkeypatch.setenv("SENTINEL_SENSOR_KEYS",json.dumps({"lab-one":KEY,"lab-two":KEY}))
    monkeypatch.setenv("SENTINEL_SENSOR_ASSETS",json.dumps({"lab-one":"workstation-1"}))
    with pytest.raises(RuntimeError,match="each sensor"):
        load_settings()
    monkeypatch.setenv("SENTINEL_SENSOR_ASSETS",json.dumps({"lab-one":"workstation-1","lab-two":"server-2"}))
    assert load_settings().sensor_assets["lab-two"]=="server-2"

def test_reconfiguration_cannot_silently_change_existing_binding(tmp_path):
    client,cfg=enrolled_client(tmp_path)
    assert beat(client).status_code==202
    newer=Settings(database_url=cfg.database_url,operator_token=OP,audit_key=AUDIT,
                   sensor_keys={"lab-one":KEY},frontend_origins=cfg.frontend_origins,
                   sensor_assets={"lab-one":"reassigned"})
    other=TestClient(create_app(newer))
    assert beat(other,body=b'{"asset_id":"reassigned"}').status_code==403
    assert coverage(other)["sensors"][0]["asset_id"]=="workstation-1"
