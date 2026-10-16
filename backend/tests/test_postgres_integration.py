"""Real PostgreSQL CI validation (skipped when service is not available)."""
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from sentinel.app import create_app
from sentinel.database import migrate, verify_schema
from sentinel.models import Alert, AuditHead, AuditRecord, SecurityEvent, SensorStatus
from test_api import OP, KEY, AUDIT, auth, post_event
from sentinel.settings import Settings

URL = os.environ.get("SENTINEL_TEST_POSTGRES_URL")


@pytest.mark.skipif(not URL, reason="PostgreSQL service only in dedicated CI job")
def test_postgres_versioned_schema_and_concurrent_writers():
    if not URL.startswith("postgresql+psycopg://"):
        raise RuntimeError("PostgreSQL test URL must use psycopg")
    migrate(URL)
    engine = create_engine(URL)
    verify_schema(engine)
    settings = Settings(database_url=URL, operator_token=OP,
                        audit_key=AUDIT, sensor_keys={"lab-one":KEY},
                        frontend_origins=("http://localhost:3000",))
    client = TestClient(create_app(settings))
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(lambda _: post_event(client).status_code, range(12)))
    assert statuses == [202] * 12
    result = client.get("/api/v1/audit/integrity", headers=auth())
    assert result.status_code == 200 and result.json()["valid"] is True
    alerts = client.get("/api/v1/alerts", headers=auth()).json()
    assert len(alerts) == 1 and alerts[0]["evidence_count"] >= 5
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 12
        assert session.get(AuditHead, 1).entry_count == session.scalar(select(func.count()).select_from(AuditRecord))
    engine.dispose()


@pytest.mark.skipif(not URL, reason="PostgreSQL service only in dedicated CI job")
def test_postgres_live_credential_revocation_and_rotation(tmp_path):
    """No mocks: the real PostgreSQL database evaluates current credential state per request."""
    from sentinel.credential_lifecycle import create_or_rotate, revoke_credential
    from sentinel.settings import Settings
    migrate(URL)
    secret = tmp_path / "postgres-admin.secret"
    admin_id = create_or_rotate(URL, AUDIT, operator_id="postgres-admin", role="admin",
                                valid_days=7, secret_file=secret)
    token = secret.read_text().strip()
    db_settings = Settings(database_url=URL, operator_token="", audit_key=AUDIT,
                           sensor_keys={"lab-one": KEY}, frontend_origins=("http://localhost:3000",),
                           auth_mode="database")
    client = TestClient(create_app(db_settings))
    assert client.get("/api/v1/session", headers={"Authorization": "Bearer " + token}).status_code == 200
    rotated_file = tmp_path / "postgres-rotated.secret"
    create_or_rotate(URL, AUDIT, operator_id="postgres-admin", role=None,
                     previous_id=admin_id, valid_days=14, secret_file=rotated_file)
    assert client.get("/api/v1/session", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert client.get("/api/v1/session", headers={"Authorization": "Bearer " + rotated_file.read_text().strip()}).status_code == 200


@pytest.mark.skipif(not URL, reason="PostgreSQL service only in dedicated CI job")
def test_postgres_sensor_heartbeat_and_atomic_event_count():
    from test_sensor_health import beat
    migrate(URL)
    app = create_app(Settings(database_url=URL, operator_token=OP, audit_key=AUDIT,
        sensor_keys={"lab-one": KEY}, frontend_origins=("http://localhost:3000",)))
    client = TestClient(app)
    result = beat(client)
    assert result.status_code == 202, result.text
    health = client.get("/api/v1/sensors", headers=auth()).json()['sensors'][0]
    assert health['status'] == 'healthy' and health['heartbeat_count'] >= 1
    engine = create_engine(URL)
    with Session(engine) as session:
        assert session.get(SensorStatus, 'lab-one').heartbeat_count >= 1
    engine.dispose()
