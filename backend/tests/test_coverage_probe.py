"""Operational coverage regression: authenticated inventory, fail-closed parsing and token secrecy."""
import json
from pathlib import Path
import pytest

from sentinel.coverage_probe import assess, CoverageProbeError, read_private_token, fetch_coverage
from scripts.check_sensor_coverage import main
from test_api import client_for, auth, OP
from test_sensor_health import beat


def sample(status="never_seen", mode="first_contact"):
    return {"sensors": [{"sensor_id": "lab-one", "status": status, "binding_mode": mode}],
            "summary": {"configured": 1, "healthy": int(status == "healthy"),
                        "gaps": int(status != "healthy"), "explicitly_enrolled": int(mode == "explicit")}}


def test_real_authenticated_api_changes_gap_to_healthy_without_alerts(tmp_path):
    client, _ = client_for(tmp_path)
    assert client.get("/api/v1/sensors").status_code == 401
    before = client.get("/api/v1/alerts", headers=auth()).json()
    initial = assess(client.get("/api/v1/sensors", headers=auth()).json())
    assert initial.never_seen == 1 and not initial.clear and initial.gaps == ("lab-one",)
    assert beat(client).status_code == 202
    current = assess(client.get("/api/v1/sensors", headers=auth()).json())
    assert current.clear and current.healthy == 1 and not current.gaps
    assert client.get("/api/v1/alerts", headers=auth()).json() == before


def test_false_green_and_bad_inventories_are_rejected():
    wrong = sample("stale")
    wrong["summary"]["gaps"] = 0
    for payload in [
        wrong, sample("unrecognized"), {"sensors": [], "summary": {}},
        {"sensors": [sample()["sensors"][0]] * 2, "summary": sample()["summary"]},
        {"sensors": [{"sensor_id": "../../../x", "status": "healthy", "binding_mode": "explicit"}],
         "summary": sample()["summary"]},
    ]:
        with pytest.raises(CoverageProbeError):
            assess(payload)


def test_summary_does_not_expose_sensor_identity():
    result = assess(sample("healthy"))
    assert result.clear and "lab-one" not in json.dumps(result.summary())


def test_private_token_permissions_symlinks_and_size(tmp_path):
    token = tmp_path / "viewer.token"
    token.write_text(OP + "\n")
    token.chmod(0o600)
    assert read_private_token(token) == OP
    token.chmod(0o644)
    with pytest.raises(CoverageProbeError, match="private"):
        read_private_token(token)
    token.chmod(0o600)
    link = tmp_path / "shortcut"
    link.symlink_to(token)
    with pytest.raises(CoverageProbeError):
        read_private_token(link)
    token.write_text("short")
    with pytest.raises(CoverageProbeError):
        read_private_token(token)
    with pytest.raises(CoverageProbeError, match="absolute"):
        read_private_token(Path("viewer.token"))


def test_cli_exit_codes_and_no_token_disclosure(tmp_path, monkeypatch, capsys):
    import scripts.check_sensor_coverage as command
    token = tmp_path / "coverage.token"
    token.write_text(OP)
    token.chmod(0o600)
    monkeypatch.setattr(command, "fetch_coverage", lambda **kw: assess(sample("healthy")))
    assert main(["--token-file", str(token), "--json"]) == 0
    observed = capsys.readouterr()
    assert '"coverage_clear": true' in observed.out
    assert OP not in observed.out + observed.err
    monkeypatch.setattr(command, "fetch_coverage", lambda **kw: assess(sample("stale")))
    assert main(["--token-file", str(token)]) == 2
    observed = capsys.readouterr()
    assert "GAP" in observed.out and OP not in observed.out + observed.err
    def failure(**kwargs):
        raise CoverageProbeError("Local coverage probe connection failed")
    monkeypatch.setattr(command, "fetch_coverage", failure)
    assert main(["--token-file", str(token)]) == 1
    observed = capsys.readouterr()
    assert OP not in observed.out + observed.err


def test_fixed_loopback_destination_and_response_contract(monkeypatch):
    import sentinel.coverage_probe as module
    calls = []
    class Reply:
        status = 200
        def getheader(self, name, default=None):
            return "application/json" if name == "Content-Type" else default
        def read(self, count):
            return json.dumps(sample("healthy")).encode()
    class FakeHTTP:
        def __init__(self, host, port, timeout):
            calls.append(("host", host, port, timeout))
        def request(self, method, route, headers):
            calls.append(("request", method, route, headers["Authorization"]))
        def getresponse(self): return Reply()
        def close(self): pass
    monkeypatch.setattr(module.http.client, "HTTPConnection", FakeHTTP)
    assert fetch_coverage(port=8000, token=OP).clear
    assert calls[0][1] == "127.0.0.1"
    assert calls[1][2] == "/api/v1/sensors"
    with pytest.raises(CoverageProbeError):
        fetch_coverage(port=0, token=OP)
    assert len(calls) == 2
