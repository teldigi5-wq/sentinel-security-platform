"""Pre-deployment contract checks; CI does not simulate a running systemd host."""
import os
from pathlib import Path

import pytest
from sentinel.collectors.linux_ssh import CollectorError, read_private_sensor_key, resolve_sensor_key

ROOT = Path(__file__).resolve().parents[2]
KEY = "K" * 48


def test_reads_owned_private_sensor_key(tmp_path):
    key = tmp_path / "collector.key"
    key.write_text(KEY + "\n")
    key.chmod(0o600)
    assert read_private_sensor_key(key) == KEY
    assert resolve_sensor_key(key_file=key, sensor_id="linux-ssh-01", environ={}) == KEY


def test_rejects_relative_unprotected_and_symlinked_key_files(tmp_path):
    key = tmp_path / "collector.key"
    key.write_text(KEY)
    key.chmod(0o600)
    with pytest.raises(CollectorError, match="absolute"):
        read_private_sensor_key(Path("collector.key"))
    key.chmod(0o644)
    with pytest.raises(CollectorError, match="private"):
        read_private_sensor_key(key)
    key.chmod(0o600)
    link = tmp_path / "key-link"
    link.symlink_to(key)
    with pytest.raises(CollectorError):
        read_private_sensor_key(link)


def test_rejects_invalid_nonregular_or_oversized_keys(tmp_path):
    with pytest.raises(CollectorError, match="regular"):
        read_private_sensor_key(tmp_path)
    key = tmp_path / "collector.key"
    key.write_text("Z" * 513)
    key.chmod(0o600)
    with pytest.raises(CollectorError, match="oversized"):
        read_private_sensor_key(key)
    key.write_text("short")
    with pytest.raises(CollectorError, match="format"):
        read_private_sensor_key(key)


def test_rejects_multiple_secret_sources(tmp_path):
    key = tmp_path / "collector.key"
    key.write_text(KEY)
    key.chmod(0o600)
    with pytest.raises(CollectorError, match="Conflicting"):
        resolve_sensor_key(key_file=key, sensor_id="linux-ssh-01",
                           environ={"SENTINEL_SENSOR_KEYS": '{"linux-ssh-01":"x"}'})


def test_existing_environment_mode_still_supported():
    assert resolve_sensor_key(key_file=None, sensor_id="linux-ssh-01",
                              environ={"SENTINEL_SENSOR_KEYS": '{"linux-ssh-01":"' + KEY + '"}'}) == KEY
    with pytest.raises(CollectorError, match="missing"):
        resolve_sensor_key(key_file=None, sensor_id="not-enrolled", environ={})
    with pytest.raises(CollectorError, match="invalid"):
        resolve_sensor_key(key_file=None, sensor_id="test", environ={"SENTINEL_SENSOR_KEYS": "broken"})


def test_unit_is_unprivileged_local_and_never_contains_keys():
    unit = (ROOT / "deploy/linux/systemd/sentinel-ssh-collector.service").read_text()
    env = (ROOT / "deploy/linux/collector.conf.example").read_text()
    for required in ["User=sentinel-sensor", "NoNewPrivileges=yes", "ProtectSystem=strict",
                     "StateDirectoryMode=0700", "IPAddressDeny=any", "IPAddressAllow=localhost",
                     "--sensor-key-file /etc/sentinel/collector.key", "--follow"]:
        assert required in unit
    assert "SENTINEL_SENSOR_KEYS=" not in unit
    assert "SENTINEL_SENSOR_KEYS=" not in env
    assert "collector.key" not in env
    assert "ExecStart=/bin/sh" not in unit and "ExecStart=/bin/bash" not in unit
