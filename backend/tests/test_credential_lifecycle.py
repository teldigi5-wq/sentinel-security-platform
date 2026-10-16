"""Real SQLite + FastAPI credential lifecycle and security regression."""
import json
import os
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sentinel.app import create_app
from sentinel.audit import verify_chain
from sentinel.credential_lifecycle import create_or_rotate, revoke_credential, list_credentials
from sentinel.database import migrate
from sentinel.models import OperatorCredential, utcnow
from sentinel.settings import Settings, load_settings
from test_api import AUDIT, KEY, OP

def prepared(tmp_path):
    url=f"sqlite:///{tmp_path/'identities.db'}"
    migrate(url)
    outfile=tmp_path/"admin.secret"
    admin_id=create_or_rotate(url,AUDIT,operator_id="soc-admin",role="admin",
                              valid_days=30,secret_file=outfile)
    config=Settings(database_url=url,operator_token="",audit_key=AUDIT,
                    sensor_keys={"lab-one":KEY},frontend_origins=("http://localhost:3000",),
                    auth_mode="database")
    return url,config,admin_id,outfile.read_text().strip()

def bearer(token):
    return {"Authorization":"Bearer "+token}

def test_database_mode_fails_closed_without_admin_and_never_accepts_static(tmp_path):
    url=f"sqlite:///{tmp_path/'empty.db'}"
    migrate(url)
    cfg=Settings(database_url=url,operator_token="",audit_key=AUDIT,
                 sensor_keys={"lab-one":KEY},frontend_origins=("http://localhost:3000",),auth_mode="database")
    with pytest.raises(RuntimeError,match="active admin"):
        create_app(cfg)
    bad=Settings(database_url=url,operator_token=OP,audit_key=AUDIT,
                 sensor_keys={"lab-one":KEY},frontend_origins=("http://localhost:3000",),auth_mode="database")
    with pytest.raises(RuntimeError,match="forbids static"):
        create_app(bad)

def test_live_enroll_roles_immediate_revoke_and_private_file(tmp_path):
    url,cfg,_,admin=prepared(tmp_path)
    file=tmp_path/"viewer.secret"
    viewer_id=create_or_rotate(url,AUDIT,operator_id="viewer.one",role="viewer",
                               valid_days=7,secret_file=file)
    viewer=file.read_text().strip()
    client=TestClient(create_app(cfg))
    assert client.get("/api/v1/session",headers=bearer(admin)).json()["role"]=="admin"
    assert client.get("/api/v1/overview",headers=bearer(viewer)).status_code==200
    assert client.get("/api/v1/audit/integrity",headers=bearer(viewer)).status_code==403
    assert client.get("/api/v1/session",headers=bearer(OP)).status_code==401
    assert not(file.stat().st_mode & 0o077)
    revoke_credential(url,AUDIT,viewer_id)
    assert client.get("/api/v1/session",headers=bearer(viewer)).status_code==401
    with Session(create_engine(url)) as s:
        assert verify_chain(s,AUDIT)

def test_rotation_replaces_token_atomically(tmp_path):
    url,cfg,admin_id,old=prepared(tmp_path)
    client=TestClient(create_app(cfg))
    file=tmp_path/"new.secret"
    newid=create_or_rotate(url,AUDIT,operator_id="soc-admin",role=None,valid_days=45,
                           previous_id=admin_id,secret_file=file)
    assert newid!=admin_id
    assert client.get("/api/v1/session",headers=bearer(old)).status_code==401
    assert client.get("/api/v1/session",headers=bearer(file.read_text().strip())).status_code==200
    assert [x["status"] for x in list_credentials(url,AUDIT)]==["revoked","active"]
    with pytest.raises(ValueError,match="not active"):
        create_or_rotate(url,AUDIT,operator_id="soc-admin",role=None,valid_days=7,
                         previous_id=admin_id,secret_file=tmp_path/"unused.secret")

def test_failed_output_or_wrong_audit_key_do_not_rotate(tmp_path):
    url,cfg,admin_id,old=prepared(tmp_path)
    with pytest.raises(FileExistsError):
        create_or_rotate(url,AUDIT,operator_id="soc-admin",role=None,valid_days=7,
                         previous_id=admin_id,secret_file=tmp_path/"admin.secret")
    with pytest.raises(RuntimeError,match="Audit integrity"):
        create_or_rotate(url,"x"*48,operator_id="soc-admin",role=None,valid_days=7,
                         previous_id=admin_id,secret_file=tmp_path/"invalid.secret")
    assert not (tmp_path/"invalid.secret").exists()
    assert TestClient(create_app(cfg)).get("/api/v1/session",headers=bearer(old)).status_code==200

def test_refuse_revoke_last_admin_and_enforce_expiry_live(tmp_path):
    url,cfg,admin_id,old=prepared(tmp_path)
    with pytest.raises(ValueError,match="last active admin"):
        revoke_credential(url,AUDIT,admin_id)
    viewer_file=tmp_path/"viewer.secret"
    viewer_id=create_or_rotate(url,AUDIT,operator_id="viewer.one",role="viewer",
                               valid_days=1,secret_file=viewer_file)
    viewer=viewer_file.read_text().strip()
    client=TestClient(create_app(cfg))
    assert client.get("/api/v1/session",headers=bearer(viewer)).status_code==200
    with Session(create_engine(url)) as s:
        row=s.get(OperatorCredential,viewer_id)
        row.expires_at=utcnow()-timedelta(minutes=1)
        s.commit()
    assert client.get("/api/v1/session",headers=bearer(viewer)).status_code==401
    assert client.get("/api/v1/session",headers=bearer(old)).status_code==200

def test_invalid_ttl_symlinks_and_bad_operator_rejected(tmp_path):
    url,_,_,_=prepared(tmp_path)
    for days in (-1,0,91,True):
        with pytest.raises(ValueError,match="validity"):
            create_or_rotate(url,AUDIT,operator_id="viewer.one",role="viewer",
                             valid_days=days,secret_file=tmp_path/"unused.secret")
    with pytest.raises(ValueError,match="Invalid operator ID"):
        create_or_rotate(url,AUDIT,operator_id="../wrong",role="viewer",valid_days=7,
                         secret_file=tmp_path/"unused.secret")
    link=tmp_path/"linked.secret"
    link.symlink_to(tmp_path/"admin.secret")
    with pytest.raises(ValueError,match="symbolic link"):
        create_or_rotate(url,AUDIT,operator_id="viewer.one",role="viewer",
                         valid_days=7,secret_file=link)

def test_database_mode_settings_reject_legacy_fallback(monkeypatch):
    monkeypatch.setenv("SENTINEL_AUDIT_KEY",AUDIT)
    monkeypatch.setenv("SENTINEL_SENSOR_KEYS",json.dumps({"lab-one":KEY}))
    monkeypatch.setenv("SENTINEL_AUTH_MODE","database")
    monkeypatch.delenv("SENTINEL_OPERATOR_TOKEN",raising=False)
    monkeypatch.delenv("SENTINEL_OPERATORS",raising=False)
    assert load_settings().auth_mode=="database"
    monkeypatch.setenv("SENTINEL_OPERATOR_TOKEN",OP)
    with pytest.raises(RuntimeError,match="forbids"):
        load_settings()
