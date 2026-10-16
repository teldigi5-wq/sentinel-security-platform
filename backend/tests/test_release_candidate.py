"""Cross-boundary v0.17 release-candidate checks; SQLite fixture, NOT host certification.

The candidate must preserve identity, sensor enrollment, incident evidence, migration,
backup, and offline export behavior when used in one database lifecycle.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from sentinel.app import create_app
from sentinel.audit import verify_case_decisions, verify_chain
from sentinel.backup import create_backup, restore_backup, verify_backup
from sentinel.credential_lifecycle import create_or_rotate, revoke_credential
from sentinel.database import HEAD_REVISION, alembic_config, migrate, verify_schema
from sentinel.evidence_export import export_event_evidence, verify_event_export
from sentinel.models import Alert, AlertDecision, AuditRecord, SecurityEvent, SensorStatus
from sentinel.settings import Settings
from test_api import AUDIT, KEY, OP, payload, post_event
from test_sensor_health import beat


def _headers(token: str) -> dict:
    return {"Authorization": "Bearer " + token}


def test_alembic_migrations_have_one_connected_head():
    """Migration forks and untracked heads cannot silently become a release."""
    scripts = ScriptDirectory.from_config(alembic_config("sqlite:///not-opened.db"))
    assert scripts.get_heads() == [HEAD_REVISION]
    revisions = list(scripts.walk_revisions())
    assert revisions and len(revisions) == len({rev.revision for rev in revisions})
    assert sum(rev.down_revision is None for rev in revisions) == 1
    assert all(rev.is_branch_point is False for rev in revisions)


def test_cross_feature_identity_sensor_case_recovery_export(tmp_path: Path):
    """One fully migrated database survives an actual multi-feature API lifecycle."""
    db = tmp_path / "candidate.sqlite3"
    url = f"sqlite:///{db}"
    migrate(url)
    admin_file = tmp_path / "admin.token"
    analyst_file = tmp_path / "analyst.token"
    admin_id = create_or_rotate(url, AUDIT, operator_id="rc-admin", role="admin",
                                valid_days=3, secret_file=admin_file)
    analyst_id = create_or_rotate(url, AUDIT, operator_id="rc-analyst", role="analyst",
                                  valid_days=3, secret_file=analyst_file)
    admin_token, analyst_token = admin_file.read_text().strip(), analyst_file.read_text().strip()
    cfg = Settings(database_url=url, operator_token="", audit_key=AUDIT,
                   sensor_keys={"lab-one": KEY}, sensor_assets={"lab-one": "workstation-1"},
                   frontend_origins=("http://localhost:3000",), auth_mode="database")

    with TestClient(create_app(cfg)) as client:
        assert client.get("/api/v1/session", headers=_headers(OP)).status_code == 401
        assert client.get("/api/v1/audit/integrity", headers=_headers(analyst_token)).status_code == 403
        assert client.get("/api/v1/sensors", headers=_headers(admin_token)).json()["summary"]["gaps"] == 1
        assert beat(client).status_code == 202
        assert post_event(client, payload(asset_id="imposter")).status_code == 403
        for _ in range(5):
            assert post_event(client).status_code == 202
        alerts = client.get("/api/v1/alerts", headers=_headers(analyst_token)).json()
        assert len(alerts) == 1 and alerts[0]["evidence_count"] == 5
        alert_id = alerts[0]["id"]
        transition = client.post(f"/api/v1/alerts/{alert_id}/transition",
                                 headers=_headers(analyst_token), json={
            "expected_state": "open", "new_state": "investigating",
            "reason": "Cross-feature release candidate evidence reviewed."})
        assert transition.status_code == 200, transition.text
        assert client.get("/api/v1/audit/integrity", headers=_headers(admin_token)).json()["valid"] is True
        assert client.get("/api/v1/sensors", headers=_headers(admin_token)).json()["summary"]["gaps"] == 0

        revoke_credential(url, AUDIT, analyst_id)
        assert client.get("/api/v1/session", headers=_headers(analyst_token)).status_code == 401
        assert client.get("/api/v1/session", headers=_headers(admin_token)).status_code == 200
        assert client.post(f"/api/v1/alerts/{alert_id}/transition", headers=_headers(analyst_token),
                           json={"expected_state": "investigating", "new_state": "resolved",
                                 "reason": "Revoked credential must not modify incident."}).status_code == 401

    # An offline recovery drill occurs after the API stops; no source mutation.
    engine = create_engine(url)
    try:
        verify_schema(engine)
        with Session(engine) as session:
            before = tuple(session.scalar(select(func.count()).select_from(model)) for model in
                           (SecurityEvent, Alert, AlertDecision, AuditRecord))
            assert before[0] == 5 and before[1] == 1 and before[2] == 1
            assert verify_chain(session, AUDIT) and verify_case_decisions(session)
    finally:
        engine.dispose()

    backup_dir = tmp_path / "sealed-backup"
    backup = create_backup(db, backup_dir, AUDIT)
    assert verify_backup(backup_dir, AUDIT) == backup
    restored = tmp_path / "restored.sqlite3"
    assert restore_backup(backup_dir, restored, AUDIT) == backup
    recovered_engine = create_engine(f"sqlite:///{restored}")
    try:
        verify_schema(recovered_engine)
        with Session(recovered_engine) as session:
            after = tuple(session.scalar(select(func.count()).select_from(model)) for model in
                          (SecurityEvent, Alert, AlertDecision, AuditRecord))
            assert after == before
            assert session.get(Alert, alert_id).state == "investigating"
            assert session.get(SensorStatus, "lab-one").asset_id == "workstation-1"
            assert verify_chain(session, AUDIT) and verify_case_decisions(session)
    finally:
        recovered_engine.dispose()

    # Explicit future reference instant only to select fixture records; this is
    # NOT a claim that the events aged 30 days on a real production system.
    bundle = tmp_path / "sealed-export"
    fields = export_event_evidence(restored, bundle, AUDIT, older_than_days=30,
                                   now=datetime.now(timezone.utc) + timedelta(days=31))
    assert fields["events_count"] == 5
    assert fields["evidence_links_count"] == 5
    assert verify_event_export(bundle, AUDIT) == fields
    assert verify_backup(backup_dir, AUDIT) == backup


def test_ci_python_module_entrypoints_exist():
    """Prevent CI from invoking missing Python scripts on the checked-out branch."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    targets = re.findall(r"\bpython\s+-m\s+(scripts\.[A-Za-z_][A-Za-z_0-9]*)", workflow)
    assert targets, "Expected explicit Python script entrypoints in the release workflow"
    for target in targets:
        location = root / "backend" / (target.replace(".", "/") + ".py")
        assert location.is_file(), f"CI references missing Python entrypoint: {target}"
