"""L1/L2/L3 SOC escalation tiers (v0.35): who may close which severity.

Uses the real multi-operator RBAC fixture (test_operator_rbac) rather than the
single-admin static token, so tier gating is exercised with genuine
viewer/analyst/admin identities and real database-backed authorization.
"""
from sentinel.escalation import operator_tier, required_tier, tier_name
from test_api import payload, post_event
from test_operator_rbac import configured_client, headers


def _open_medium_alert(client):
    """auth_failure bursts score as "medium" severity (see sentinel.detection)."""
    for _ in range(5):
        assert post_event(client, payload(action="auth_failure")).status_code == 202
    alerts = client.get("/api/v1/alerts", headers=headers("chief-admin")).json()
    return next(a["id"] for a in alerts if a["severity"] == "medium")


def _open_high_alert(client):
    assert post_event(client, payload(category="endpoint", action="malware_detected",
                                       source_ip=None)).status_code == 202
    alerts = client.get("/api/v1/alerts", headers=headers("chief-admin")).json()
    return next(a["id"] for a in alerts if a["severity"] == "high")


def _acknowledge(client, operator, alert_id):
    return client.post(f"/api/v1/alerts/{alert_id}/transition", headers=headers(operator), json={
        "expected_state": "open", "new_state": "investigating", "reason": "Tier-gated test triage step."})


def _close(client, operator, alert_id):
    return client.post(f"/api/v1/alerts/{alert_id}/transition", headers=headers(operator), json={
        "expected_state": "investigating", "new_state": "resolved", "reason": "Tier-gated test close step."})


def test_tier_table_matches_the_documented_soc_model():
    assert [operator_tier(r) for r in ("viewer", "analyst", "admin")] == [1, 2, 3]
    assert [tier_name(t) for t in (1, 2, 3)] == ["L1", "L2", "L3"]
    assert required_tier(("investigating", "resolved"), "low") == 2
    assert required_tier(("investigating", "resolved"), "medium") == 2
    assert required_tier(("investigating", "resolved"), "high") == 3
    # Fail closed: an unrecognized severity needs the highest tier, not the lowest.
    assert required_tier(("investigating", "resolved"), "unprecedented") == 3


def test_l2_analyst_closes_medium_severity_alone(tmp_path):
    client, _ = configured_client(tmp_path)
    alert_id = _open_medium_alert(client)
    assert _acknowledge(client, "analyst.01", alert_id).status_code == 200
    response = _close(client, "analyst.01", alert_id)
    assert response.status_code == 200, response.text
    assert client.get("/api/v1/alerts", headers=headers("chief-admin")).json()[0]["state"] == "resolved"


def test_l2_analyst_cannot_close_high_severity_must_escalate_to_l3(tmp_path):
    client, _ = configured_client(tmp_path)
    alert_id = _open_high_alert(client)
    assert _acknowledge(client, "analyst.01", alert_id).status_code == 200
    blocked = _close(client, "analyst.01", alert_id)
    assert blocked.status_code == 403
    assert "L3" in blocked.json()["detail"]
    # The rejected close must not have changed state or left a decision record.
    alerts = client.get("/api/v1/alerts", headers=headers("chief-admin")).json()
    assert alerts[0]["state"] == "investigating"
    history = client.get(f"/api/v1/alerts/{alert_id}/history", headers=headers("chief-admin")).json()
    assert [h["new_state"] for h in history] == ["investigating"]
    # L3 can close exactly the alert L2 had to hand off.
    escalated = _close(client, "chief-admin", alert_id)
    assert escalated.status_code == 200, escalated.text


def test_viewer_still_cannot_acknowledge_or_close_any_severity(tmp_path):
    """L1 (viewer) remains read-only; unchanged by this feature (see test_operator_rbac)."""
    client, _ = configured_client(tmp_path)
    medium_id = _open_medium_alert(client)
    assert _acknowledge(client, "auditor", medium_id).status_code == 403
    high_id = _open_high_alert(client)
    assert _acknowledge(client, "chief-admin", high_id).status_code == 200
    assert _close(client, "auditor", high_id).status_code == 403


def test_alerts_list_reports_the_close_tier_each_alert_needs(tmp_path):
    client, _ = configured_client(tmp_path)
    _open_medium_alert(client)
    _open_high_alert(client)
    alerts = {a["severity"]: a["close_tier"] for a in client.get("/api/v1/alerts", headers=headers("chief-admin")).json()}
    assert alerts == {"medium": "L2", "high": "L3"}


def test_session_reports_tier_and_close_high_severity_capability(tmp_path):
    client, _ = configured_client(tmp_path)
    viewer = client.get("/api/v1/session", headers=headers("auditor")).json()
    analyst = client.get("/api/v1/session", headers=headers("analyst.01")).json()
    admin = client.get("/api/v1/session", headers=headers("chief-admin")).json()
    assert (viewer["tier"], viewer["capabilities"]["close_high_severity"]) == ("L1", False)
    assert (analyst["tier"], analyst["capabilities"]["close_high_severity"]) == ("L2", False)
    assert (admin["tier"], admin["capabilities"]["close_high_severity"]) == ("L3", True)
