"""Permission and evidence tests run without root, systemd or network access."""
from pathlib import Path
import json
import os
import stat

import pytest
from sentinel.deployment_preflight import inspect_deployment
from scripts.preflight_linux_collector import main

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy/linux/systemd/sentinel-ssh-collector.service"


def setup_case(tmp_path):
    source = tmp_path / "auth.log"
    source.write_text("sshd[1]: Failed password for x from 192.0.2.7 port 42\n")
    source.chmod(0o640)
    state = tmp_path / "cursor"
    state.mkdir(mode=0o700)
    key = tmp_path / "collector.key"
    secret = "SUPER_PRIVATE_" + "K" * 48
    key.write_text(secret)
    key.chmod(0o600)
    conf = tmp_path / "collector.conf"
    conf.write_text("SENTINEL_SENSOR_ID=ssh-1\nSENTINEL_ASSET_ID=host-1\n")
    unit = tmp_path / "sentinel.service"
    unit.write_text(UNIT.read_text()
                    .replace("/var/log/auth.log", str(source))
                    .replace("/var/lib/sentinel-sensor", str(state))
                    .replace("/etc/sentinel/collector.key", str(key))
                    .replace("/etc/sentinel/collector.conf", str(conf)))
    return {"source": source, "state_dir": state, "key_file": key,
            "config_file": conf, "unit_file": unit}, secret


def checked(kwargs, **changes):
    return inspect_deployment(**(kwargs | changes), fixture=True, environ={})


def status(report, identifier):
    return next(check["result"] for check in report["checks"] if check["id"] == identifier)


def test_fixture_passes_without_mutation_or_credential_leak(tmp_path):
    kw, secret = setup_case(tmp_path)
    previous = set(tmp_path.iterdir())
    report = checked(kw)
    assert report["all_checks_passed"] and report["host_certified"] is False
    assert status(report, "service_account") == "not_verified"
    assert status(report, "root_owned_service_config") == "not_verified"
    assert secret not in json.dumps(report)
    assert set(tmp_path.iterdir()) == previous
    assert not (kw["state_dir"] / "ssh-cursor.json").exists()


def test_weak_key_and_conflicting_env_fail(tmp_path):
    kw, _ = setup_case(tmp_path)
    kw["key_file"].chmod(0o644)
    assert status(checked(kw), "private_signing_key") == "fail"
    kw["key_file"].chmod(0o600)
    r = inspect_deployment(**kw, fixture=True,
                           environ={"SENTINEL_SENSOR_KEYS": '{"ssh-1":"FAKE"}'})
    assert status(r, "private_signing_key") == "fail"
    assert "FAKE" not in json.dumps(r)


def test_log_symlink_and_private_state_permission_fail(tmp_path):
    kw, _ = setup_case(tmp_path)
    link = tmp_path / "symlink.log"
    link.symlink_to(kw["source"])
    assert status(checked(kw, source=link), "readonly_log_access") == "fail"
    kw["state_dir"].chmod(0o755)
    assert status(checked(kw), "private_cursor_storage") == "fail"


def test_invalid_cursor_rejected(tmp_path):
    kw, _ = setup_case(tmp_path)
    cursor = kw["state_dir"] / "ssh-cursor.json"
    cursor.write_text('not json')
    cursor.chmod(0o600)
    assert status(checked(kw), "private_cursor_storage") == "fail"


def test_duplicate_metadata_and_secret_injection_fail(tmp_path):
    kw, _ = setup_case(tmp_path)
    with kw["config_file"].open("a") as stream:
        stream.write("SENTINEL_SENSOR_KEYS=secret\n")
    assert status(checked(kw), "strict_metadata") == "fail"
    kw["config_file"].write_text("SENTINEL_SENSOR_ID=x\nSENTINEL_SENSOR_ID=y\nSENTINEL_ASSET_ID=z\n")
    assert status(checked(kw), "strict_metadata") == "fail"


def test_unit_dropped_hardening_or_wrong_path_fails(tmp_path):
    kw, _ = setup_case(tmp_path)
    unit = kw["unit_file"]
    unit.write_text(unit.read_text().replace("NoNewPrivileges=yes", "NoNewPrivileges=no"))
    assert status(checked(kw), "service_unit_contract") == "fail"
    unit.write_text(UNIT.read_text())
    assert status(checked(kw), "service_unit_contract") == "fail"


def test_cli_writes_private_exclusive_json_and_never_overwrites(tmp_path, capsys):
    kw, secret = setup_case(tmp_path)
    report = tmp_path / "evidence.json"
    args = []
    for flag, key in [("--source", "source"), ("--state-dir", "state_dir"),
                      ("--key-file", "key_file"), ("--config-file", "config_file"),
                      ("--unit-file", "unit_file")]:
        args += [flag, str(kw[key])]
    args += ["--fixture", "--json-out", str(report)]
    assert main(args) == 0
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert secret not in capsys.readouterr().out
    assert json.loads(report.read_text())["host_certified"] is False
    with pytest.raises(SystemExit):
        main(args)
    assert json.loads(report.read_text())["all_checks_passed"] is True


def test_unknown_service_account_fails_closed_for_real_host(tmp_path, monkeypatch):
    kw, _ = setup_case(tmp_path)
    monkeypatch.setattr("sentinel.deployment_preflight.pwd.getpwnam",
                        lambda _: (_ for _ in ()).throw(KeyError("service account not found")))
    report = inspect_deployment(**kw, fixture=False, environ={})
    assert status(report, "service_account") == "fail"
    assert not report["all_checks_passed"]


def test_unit_duplicate_directive_and_exec_pre_hook_rejected(tmp_path):
    kw, _ = setup_case(tmp_path)
    unit = kw["unit_file"]
    unit.write_text(unit.read_text().replace("NoNewPrivileges=yes",
                                             "NoNewPrivileges=yes\nNoNewPrivileges=no"))
    assert status(checked(kw), "service_unit_contract") == "fail"
    unit.write_text(UNIT.read_text().replace("Restart=on-failure",
                                            "ExecStartPre=/bin/sh -c 'echo unsafe'\nRestart=on-failure")
                    .replace("/var/log/auth.log", str(kw["source"]))
                    .replace("/var/lib/sentinel-sensor", str(kw["state_dir"]))
                    .replace("/etc/sentinel/collector.key", str(kw["key_file"]))
                    .replace("/etc/sentinel/collector.conf", str(kw["config_file"])))
    assert status(checked(kw), "service_unit_contract") == "fail"
