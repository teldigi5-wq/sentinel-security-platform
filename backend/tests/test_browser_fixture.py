"""Disposable v0.32 UI/back-end integration fixture acceptance."""
from pathlib import Path
import json
import os
import stat
import pytest
from scripts.seed_browser_fixture import prepare


def test_signed_real_fixture_and_private_secrets(tmp_path):
    result = prepare(tmp_path)
    assert result == {"events": 5, "alerts": 1, "signed_heartbeat": True, "fixture_only": True}
    record = tmp_path / "fixture.json"
    assert record.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(record.stat().st_mode) == 0o600
    data = json.loads(record.read_text())
    assert data["expectedEvents"] == 5
    assert data["expectedAlertEvidence"] == 5
    assert len(data["admin"]) > 32 and data["admin"] != data["viewer"]
    assert data["env"]["SENTINEL_FRONTEND_ORIGINS"] == "http://127.0.0.1:3100"
    assert data["env"]["SENTINEL_DATABASE_URL"].startswith("sqlite:///")
    assert "fixture-host" in data["env"]["SENTINEL_SENSOR_ASSETS"]
    with pytest.raises(ValueError, match="already exist"):
        prepare(tmp_path)


def test_seeding_refuses_world_readable_directory(tmp_path):
    tmp_path.chmod(0o755)
    try:
        with pytest.raises(ValueError, match="mode 0700"):
            prepare(tmp_path)
    finally:
        tmp_path.chmod(0o700)


def test_seeding_refuses_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="absolute"):
        prepare(Path("."))