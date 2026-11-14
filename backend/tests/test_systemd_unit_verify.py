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


# --- v0.34: systemd 259 / Ubuntu 26.04 runner drift -------------------------
# The new parser warns about unrelated host units it loads as dependencies.
# Those must be tolerated ONLY when attributable to another host unit file.
from sentinel.systemd_unit_verify import _host_only_diagnostics  # noqa: E402

COPY = Path('/tmp/sentinel-unit-parser-x/sentinel-ssh-collector.service')
HOST_WARNING = ('/usr/lib/systemd/system/walinuxagent.service:21: '
                'Support for option CPUAccounting= has been removed and it is ignored')


def _result(stderr='', stdout='', code=0):
    return subprocess.CompletedProcess(['systemd-analyze'], code, stdout, stderr)


def test_host_unit_warnings_are_counted_not_fatal():
    assert _host_only_diagnostics(_result(HOST_WARNING + '\n' + HOST_WARNING.replace('walinuxagent', 'xfs_scrub_all')), COPY) == 2
    assert _host_only_diagnostics(_result(''), COPY) == 0


@pytest.mark.parametrize('stderr', [
    f'{COPY}:20: Unknown key name \'ImaginarySentinelOption\' in section \'Service\', ignoring.',
    '/usr/lib/systemd/system/sentinel-ssh-collector.service:3: Unknown key, ignoring.',
    'sentinel-ssh-collector.service: Command /x is not executable: No such file or directory',
    'Failed to load unit: something unexpected',
    HOST_WARNING + '\nunclassified trailing line',
    '/home/runner/evil.service:1: path outside systemd host roots',
    # Host-unit diagnostics OTHER than the verified removed-option class fail.
    "/usr/lib/systemd/system/walinuxagent.service:9: Unknown key name 'Foo' in section 'Service', ignoring.",
    '/usr/lib/systemd/system/network.target:3: Failed to parse value, ignoring: x',
    '/etc/systemd/system/x.service:1: Unit configured to use KillMode=none. This is unsafe',
    '/usr/lib/systemd/system/a.service:2: Support for option CPUAccounting= has been removed and it is ignored; extra',
])
def test_unit_or_unattributable_diagnostics_still_fail_closed(stderr):
    assert _host_only_diagnostics(_result(stderr), COPY) is None


def test_nonzero_exit_or_stdout_fails_even_with_host_only_warnings():
    assert _host_only_diagnostics(_result(HOST_WARNING, code=1), COPY) is None
    assert _host_only_diagnostics(_result(HOST_WARNING, stdout='x'), COPY) is None
    assert _host_only_diagnostics(_result(HOST_WARNING * 200), COPY) is None
