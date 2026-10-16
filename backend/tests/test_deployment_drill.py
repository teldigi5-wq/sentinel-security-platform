"""Isolated end-to-end data-plane recovery drill; no external host access."""
import json
import os
from pathlib import Path

import pytest
from sentinel.deployment_drill import execute
from scripts.drill_linux_collector import main, write_private_report


def test_full_fixture_drill_including_rotation_replay_and_outage():
    result = execute()
    assert result["all_passed"], result["checks"]
    assert result["event_samples"] == 7
    assert result["host_certified"] is False
    assert len(result["checks"]) >= 12
    assert {"signed_log_ingestion", "deterministic_nonce_retry", "simulated_outage_detected",
            "rotation_detected", "audit_chain_valid"} <= {x["id"] for x in result["checks"]}
    assert all(x["result"] == "pass" for x in result["checks"])


def test_qualification_report_never_contains_secrets_logs_or_asset_ids():
    report = json.dumps(execute())
    for sensitive in ("fixture-only-kkkk", "198.51.100.42", "drill-host", "drill-sensor",
                      "Failed password", "ssh-cursor.json", "isolated.db"):
        assert sensitive not in report
    assert "isolated-synthetic-fixture-only" in report


def test_evidence_file_is_private_and_exclusive(tmp_path):
    target = tmp_path / "drill.json"
    code = main(["--json-out", str(target)])
    assert code == 0
    assert target.stat().st_mode & 0o777 == 0o600
    original = target.read_bytes()
    with pytest.raises(SystemExit):
        main(["--json-out", str(target)])
    assert target.read_bytes() == original


def test_symlink_evidence_never_overwritten(tmp_path):
    existing = tmp_path / "existing"
    existing.write_text("important")
    link = tmp_path / "report.json"
    link.symlink_to(existing)
    with pytest.raises(FileExistsError):
        write_private_report(link, {"all_passed": True})
    assert existing.read_text() == "important"


def test_failed_qualification_is_reported_not_suppressed(monkeypatch):
    import sentinel.deployment_drill as module
    def broken_migration(url):
        raise RuntimeError("injected failure with private context")
    monkeypatch.setattr(module, "migrate", broken_migration)
    result = module.execute()
    assert result["all_passed"] is False
    assert result["checks"][-1] == {"id":"unexpected_failure", "result":"fail"}
    assert "private context" not in json.dumps(result)
