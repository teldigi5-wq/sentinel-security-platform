"""Read-only host observation must fail closed and never expose host secrets."""
import json
import stat
from types import SimpleNamespace

import pytest

from sentinel.coverage_probe import assess, CoverageProbeError
from sentinel.host_observation import HostObservationError, observe, UNIT, _FIELDS
from scripts.observe_linux_host import main

TOKEN = 'A' * 64
SENSOR = 'linux-ssh-01'


def systemd_output(**replacements):
    values = {
        'Id': UNIT, 'LoadState': 'loaded', 'ActiveState': 'active',
        'SubState': 'running', 'User': 'sentinel-sensor', 'Group': 'sentinel-sensor',
        'FragmentPath': f'/etc/systemd/system/{UNIT}', 'MainPID': '4321',
        'NRestarts': '0', 'NeedDaemonReload': 'no',
    } | replacements
    return '\n'.join(f'{key}={values[key]}' for key in _FIELDS) + '\n'


def fixture_coverage(state='healthy', mode='explicit', sensor=SENSOR):
    return assess({'sensors': [{'sensor_id': sensor, 'status': state, 'binding_mode': mode}],
                   'summary': {'configured': 1, 'healthy': int(state == 'healthy'),
                               'gaps': int(state != 'healthy'),
                               'explicitly_enrolled': int(mode == 'explicit')}})


def run(*, output=None, status='healthy', binding='explicit', platform='Linux', identity=SENSOR):
    calls = []
    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=systemd_output() if output is None else output)
    report = observe(sensor_id=identity, port=8000, token=TOKEN,
                     runner=runner, probe=lambda **kw: fixture_coverage(status, binding),
                     system_name=platform)
    return report, calls


def test_live_observation_checks_fixed_systemctl_and_never_certifies():
    report, calls = run()
    assert report['all_checks_passed'] and report['host_certified'] is False
    assert len(calls) == 1 and calls[0][0][0] == '/usr/bin/systemctl'
    assert 'show' in calls[0][0] and UNIT in calls[0][0]
    assert calls[0][1]['timeout'] == 5
    assert calls[0][1]['env'] == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    assert report['restart_count_observed'] == 0
    assert TOKEN not in json.dumps(report) and SENSOR not in json.dumps(report)
    assert '/etc' not in json.dumps(report)


@pytest.mark.parametrize('state,binding', [
    ('stale', 'explicit'), ('never_seen', 'explicit'), ('healthy', 'first_contact')
])
def test_unhealthy_or_unenrolled_is_not_qualified(state, binding):
    report, _ = run(status=state, binding=binding)
    assert not report['all_checks_passed'] and not report['host_certified']
    assert report['sensor_contact'] == state


@pytest.mark.parametrize('override', [
    {'MainPID': '0'}, {'User': 'root'}, {'NeedDaemonReload': 'yes'},
    {'ActiveState': 'failed'}, {'FragmentPath': '/tmp/unsafe.service'},
])
def test_wrong_service_contract_fails(override):
    report, _ = run(output=systemd_output(**override))
    assert not report['all_checks_passed']


@pytest.mark.parametrize('output', [
    systemd_output() + 'User=root\n',
    systemd_output().replace('MainPID=4321', 'MainPID=NaN'),
    systemd_output().replace('Group=sentinel-sensor\n', ''),
    'malformed\n',
    systemd_output() + 'unexpected=secret\n',
    systemd_output() * 1000,
])
def test_malformed_systemctl_fails_closed(output):
    with pytest.raises(HostObservationError):
        run(output=output)


def test_non_linux_and_missing_sensor_and_bad_probe_fail():
    with pytest.raises(HostObservationError):
        run(platform='Windows')
    with pytest.raises(HostObservationError):
        run(identity='../bad')
    with pytest.raises(HostObservationError):
        run(identity='different-valid-id')
    with pytest.raises(HostObservationError):
        observe(sensor_id=SENSOR, port=8000, token=TOKEN,
                runner=lambda *_a, **_k: SimpleNamespace(returncode=0, stdout=systemd_output()),
                probe=lambda **_kw: (_ for _ in ()).throw(CoverageProbeError('secret=' + TOKEN)),
                system_name='Linux')


def test_systemd_timeout_and_command_failure_fail_closed():
    import subprocess
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 5)
    with pytest.raises(HostObservationError):
        observe(sensor_id=SENSOR, port=8000, token=TOKEN, runner=timeout,
                probe=lambda **kw: fixture_coverage(), system_name='Linux')
    with pytest.raises(HostObservationError):
        observe(sensor_id=SENSOR, port=8000, token=TOKEN,
                runner=lambda *_a, **_kw: SimpleNamespace(returncode=1, stdout='private=secret'),
                probe=lambda **kw: fixture_coverage(), system_name='Linux')


def test_cli_return_codes_and_private_exclusive_report(tmp_path, monkeypatch, capsys):
    import scripts.observe_linux_host as cli
    token = tmp_path / 'viewer.token'
    token.write_text(TOKEN)
    token.chmod(0o600)
    report = tmp_path / 'evidence.json'
    monkeypatch.setattr(cli, 'observe', lambda **kw: run()[0])
    args = ['--sensor-id', SENSOR, '--token-file', str(token), '--json-out', str(report)]
    assert main(args) == 0
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert json.loads(report.read_text())['host_certified'] is False
    with pytest.raises(SystemExit):
        main(args)
    monkeypatch.setattr(cli, 'observe', lambda **kw: run(status='stale')[0])
    assert main(args[:-2]) == 2
    monkeypatch.setattr(cli, 'observe', lambda **kw: (_ for _ in ()).throw(HostObservationError(TOKEN)))
    assert main(args[:-2]) == 1
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err


def test_aggregate_coverage_backwards_compatible():
    assessment = fixture_coverage()
    assert assessment.clear
    assert assessment.sensor_states == ((SENSOR, 'healthy', 'explicit'),)
    assert SENSOR not in json.dumps(assessment.summary())


def test_malformed_nested_inventory_never_crashes_with_type_error():
    with pytest.raises(CoverageProbeError):
        assess({'sensors': [{'sensor_id': SENSOR, 'status': {'unsafe': 'value'},
                              'binding_mode': 'explicit'}],
                'summary': {'configured': 1, 'healthy': 1,
                            'gaps': 0, 'explicitly_enrolled': 1}})
