"""Triage integration regressions run against a real SQLite transaction boundary."""
from test_api import client_for, post_event, payload, auth


def make_alert(client):
    r = post_event(client, payload(category="endpoint", action="malware_detected", source_ip=None))
    assert r.status_code == 202
    return r.json()["new_alert_ids"][0]


def test_operator_can_investigate_resolve_reopen_with_history(tmp_path):
    client, _ = client_for(tmp_path)
    alert_id = make_alert(client)
    url = f"/api/v1/alerts/{alert_id}/transition"
    history_url = f"/api/v1/alerts/{alert_id}/history"
    assert client.get(history_url).status_code == 401
    for old, new in [("open", "investigating"), ("investigating", "resolved"), ("resolved", "investigating")]:
        response = client.post(url, headers=auth(), json={
            "expected_state": old, "new_state": new, "reason": "Reviewed event evidence in controlled test."})
        assert response.status_code == 200, response.text
        alerts = client.get("/api/v1/alerts", headers=auth()).json()
        assert alerts[0]["state"] == new
    history = client.get(history_url, headers=auth()).json()
    assert [d["new_state"] for d in history] == ["investigating", "resolved", "investigating"]
    assert history[0]["actor"] == "operator"
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"] is True


def test_triage_fails_closed_with_invalid_authorization_state_and_input(tmp_path):
    client, _ = client_for(tmp_path)
    alert_id = make_alert(client)
    route = f"/api/v1/alerts/{alert_id}/transition"
    valid = {"expected_state": "open", "new_state": "investigating", "reason": "Test evidence supports triage."}
    assert client.post(route, json=valid).status_code == 401
    assert client.post(route, headers={"Authorization": "Bearer wrong"}, json=valid).status_code == 401
    assert client.post(route, headers=auth(), json={**valid, "new_state": "resolved"}).status_code == 422
    assert client.post(route, headers=auth(), json={**valid, "reason": "short"}).status_code == 422
    assert client.post(route, headers=auth(), json={**valid, "reason": "Invalid\ncontrol char"}).status_code == 422
    assert client.post(route, headers=auth(), json={**valid, "command": "delete"}).status_code == 422
    assert client.post(route, headers=auth(), content=b"{" + b" " * 2500 + b"}").status_code == 413
    assert client.post(route, headers=auth(), json=valid).status_code == 200
    assert client.post(route, headers=auth(), json=valid).status_code == 409
    assert len(client.get(f"/api/v1/alerts/{alert_id}/history", headers=auth()).json()) == 1


def test_missing_alert_does_not_create_audit_or_decision(tmp_path):
    client, _ = client_for(tmp_path)
    instruction = {"expected_state": "open", "new_state": "investigating", "reason": "Missing alert in database."}
    assert client.post("/api/v1/alerts/00000000-0000-0000-0000-000000000000/transition", headers=auth(), json=instruction).status_code == 404
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["records"] == 0


def test_triage_cors_restricts_unauthorized_web_origins(tmp_path):
    client, _ = client_for(tmp_path)
    good = client.options("/api/v1/alerts/id/transition", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"})
    assert good.status_code == 200
    assert good.headers.get("access-control-allow-origin") == "http://localhost:3000"
    bad = client.options("/api/v1/alerts/id/transition", headers={
        "Origin": "https://example.invalid", "Access-Control-Request-Method": "POST"})
    assert bad.headers.get("access-control-allow-origin") is None


def test_mutated_decision_or_alert_state_fails_integrity_check(tmp_path):
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session
    from sentinel.models import AlertDecision
    client, settings = client_for(tmp_path)
    alert_id = make_alert(client)
    response = client.post(f"/api/v1/alerts/{alert_id}/transition", headers=auth(), json={
        "expected_state": "open", "new_state": "investigating", "reason": "Verified relevant endpoint telemetry."})
    assert response.status_code == 200
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"] is True
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        decision = session.scalars(select(AlertDecision)).first()
        decision.reason = "Edited decision rationale after the fact"
        session.commit()
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"] is False
