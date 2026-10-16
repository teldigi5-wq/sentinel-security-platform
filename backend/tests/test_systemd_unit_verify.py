"""Check real systemd-parser behavior, including warnings with exit code 0."""
import json
from pathlib import Path
import platform
import shutil
import subprocess

import pytest

from sentinel.systemd_unit_verify import UnitSyntaxError, UnitToolUnavailable, verify_unit
from scripts.verify_linux_service_unit import main

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / 'deploy/linux/systemd/sentinel-ssh-collector.service'


def _changed(tmp_path, before, after):
    source = tmp_path / UNIT.name
    source.write_text(UNIT.read_text().replace(before, after))
    return source


def test_real_systemd_parser_accepts_shipped_unit():
    if platform.system() != 'Linux' or not shutil.which('systemd-analyze'):
        pytest.skip('Only CI-hosted Linux can qualify real systemd parser')
    report = verify_unit(UNIT)
    assert report['syntax_verified'] is True
    assert report['reviewed_contract_verified'] is True
    assert report['unit_sha256'] and len(report['unit_sha256']) == 64
    assert report['service_started'] is False
    assert report['host_certified'] is False


def test_malformed_type_fails_even_when_systemd_reports_success(tmp_path):
    if platform.system() != 'Linux' or not shutil.which('systemd-analyze'):
        pytest.skip('Only CI-hosted Linux can qualify real systemd parser')
    # Unit contract itself doesn't enforce Type= value beyond exact simple; this
    # checks rejection rather than allowing unknown configuration to be ignored.
    modified = _changed(tmp_path, 'Type=simple', 'Type=impossible')
    with pytest.raises(UnitSyntaxError):
        verify_unit(modified)


def test_unknown_systemd_key_cannot_be_silently_ignored(tmp_path):
    if platform.system() != 'Linux' or not shutil.which('systemd-analyze'):
        pytest.skip('Only CI-hosted Linux can qualify real systemd parser')
    modified = _changed(tmp_path, 'PrivateTmp=yes', 'PrivateTmp=yes\nImaginarySentinelOption=yes')
    with pytest.raises(UnitSyntaxError, match='warned'):
        verify_unit(modified)
    # Demonstrate the fail-open pitfall of checking only return code.
    data = modified.read_text().replace('/opt/sentinel/venv/bin/python', '/usr/bin/true')
    fixture = tmp_path / 'parsed' / UNIT.name
    fixture.parent.mkdir()
    fixture.write_text(data)
    raw = subprocess.run([shutil.which('systemd-analyze'), 'verify', str(fixture)],
                         capture_output=True, text=True, timeout=10)
    assert raw.returncode == 0 and 'Unknown key' in raw.stderr


def test_added_execution_hook_is_forbidden(tmp_path):
    path = _changed(tmp_path, 'ExecStart=', 'ExecStartPre=/bin/true\nExecStart=')
    with pytest.raises(UnitSyntaxError):
        verify_unit(path)


def test_weakened_network_confinement_is_forbidden(tmp_path):
    path = _changed(tmp_path, 'IPAddressDeny=any', 'IPAddressDeny=')
    with pytest.raises(UnitSyntaxError):
        verify_unit(path)


def test_no_systemd_parser_fails_unknown_not_pass():
    with pytest.raises(UnitToolUnavailable):
        verify_unit(UNIT, analyzer='/path/to/nonexistent/systemd-analyze')


def test_command_output_contains_no_secret_or_host_claim(capsys):
    result = main(['--json'])
    if platform.system() != 'Linux' or not shutil.which('systemd-analyze'):
        assert result == 1
    else:
        assert result == 0
        record = json.loads(capsys.readouterr().out)
        assert record['host_certified'] is False
        assert record['service_started'] is False
        assert 'key' not in json.dumps(record).lower() or 'sha256' in record
