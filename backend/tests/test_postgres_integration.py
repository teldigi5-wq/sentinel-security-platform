"""Real PostgreSQL CI validation (skipped when service is not available)."""
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from sentinel.app import create_app
from sentinel.database import migrate, verify_schema
from sentinel.models import Alert, AuditHead, AuditRecord, SecurityEvent
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
def test_postgres_live_credential_rotation(tmp_path):
    from sentinel.credential_lifecycle import create_or_rotate
    migrate(URL)
    file=tmp_path/"postgres-admin.secret"
    admin_id=create_or_rotate(URL,AUDIT,operator_id="postgres-admin",role="admin",valid_days=7,secret_file=file)
    prior=file.read_text().strip()
    cfg=Settings(database_url=URL,operator_token="",audit_key=AUDIT,
                 sensor_keys={"lab-one":KEY},frontend_origins=("http://localhost:3000",),auth_mode="database")
    client=TestClient(create_app(cfg))
    assert client.get("/api/v1/session",headers={"Authorization":"Bearer "+prior}).status_code==200
    new_file=tmp_path/"postgres-new.secret"
    create_or_rotate(URL,AUDIT,operator_id="postgres-admin",role=None,previous_id=admin_id,
                     valid_days=30,secret_file=new_file)
    assert client.get("/api/v1/session",headers={"Authorization":"Bearer "+prior}).status_code==401
    assert client.get("/api/v1/session",headers={"Authorization":"Bearer "+new_file.read_text().strip()}).status_code==200
