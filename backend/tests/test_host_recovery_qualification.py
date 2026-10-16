"""v0.25: offline fixture qualification does not certify a Linux host."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.coverage_probe import CoverageAssessment, CoverageProbeError, assess
from sentinel.host_acceptance import (HostAcceptanceError, PHASES, capture,
                                       read_invocation, verify)
from sentinel.integrity_probe import IntegrityAssessment


class Lab:
    def __init__(self, tmp_path):
        self.dir = tmp_path / "private-evidence"
        self.boot = "first-boot"
        self.invocation = "first-service"
        self.inode = "device:11"
        self.events = 3
        self.heartbeats = 5
        self.healthy = True
        self.anchored = True
        self.now = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)

    def capture(self, stage):
        def host(**kwargs):
            assert kwargs['token'] == 'v' * 48
            return {'all_checks_passed': self.healthy}
        def coverage(**kwargs):
            return CoverageAssessment(1, 1, 0, 0, 1, (),
                                      (('sensor-01', 'healthy', 'explicit'),),
                                      (('sensor-01', self.events, self.heartbeats),))
        def integrity(**kwargs):
            return IntegrityAssessment('anchored' if self.anchored else 'integrity_failed',
                                       self.anchored, True)
        result = capture(phase=stage, directory=self.dir, sensor_id='sensor-01',
                         port=8000, token='v' * 48, observer=host,
                         coverage_fetch=coverage, integrity_fetch=integrity,
                         instance_probe=lambda: self.invocation,
                         boot_probe=lambda: self.boot,
                         log_probe=lambda: self.inode,
                         clock=lambda: self.now, system_name='Linux')
        self.now += timedelta(minutes=3)
        return result

    def restart(self):
        self.invocation = 'second-service'
        self.heartbeats += 1

    def rotate(self):
        self.inode = 'device:12'
        self.events += 1

    def reboot(self):
        self.boot = 'second-boot'
        self.invocation = 'third-service'
        self.heartbeats += 1


def test_full_operator_drill_success_and_private_files(tmp_path):
    lab = Lab(tmp_path)
    assert lab.capture('baseline')['status'] == 'pass'
    lab.restart()
    assert lab.capture('post_restart')['status'] == 'pass'
    lab.rotate()
    assert lab.capture('post_rotation')['status'] == 'pass'
    lab.reboot()
    assert lab.capture('post_reboot')['status'] == 'pass'
    result = verify(lab.dir)
    assert result['checkpoint_count'] == 4 and result['result'] == 'observed_phases_passed'
    assert result['host_certified'] is False
    assert (lab.dir.stat().st_mode & 0o777) == 0o700
    for phase in PHASES:
        checkpoint = lab.dir / f'{phase}.json'
        assert (checkpoint.stat().st_mode & 0o777) == 0o600
        raw = checkpoint.read_text()
        assert 'first-boot' not in raw and 'device:' not in raw
        assert 'second-service' not in raw and 'v' * 48 not in raw
        assert json.loads(raw)['host_certified'] is False


def test_no_actual_restart_does_not_pass(tmp_path):
    lab = Lab(tmp_path)
    lab.capture('baseline')
    lab.heartbeats += 1
    evidence = lab.capture('post_restart')
    assert evidence['status'] == 'gap'
    assert evidence['checks']['new_service_invocation'] == 'gap'
    with pytest.raises(HostAcceptanceError):
        lab.capture('post_rotation')


def test_rotation_requires_inode_change_and_later_event(tmp_path):
    lab = Lab(tmp_path)
    lab.capture('baseline')
    lab.restart()
    lab.capture('post_restart')
    lab.inode = 'device:12'
    record = lab.capture('post_rotation')
    assert record['status'] == 'gap'
    assert record['checks']['new_event_after_rotation'] == 'gap'


def test_reboot_requires_new_boot_id_and_new_contact(tmp_path):
    lab = Lab(tmp_path)
    lab.capture('baseline')
    lab.restart()
    lab.capture('post_restart')
    lab.rotate()
    lab.capture('post_rotation')
    lab.invocation = 'third-service'
    lab.heartbeats += 1
    assert lab.capture('post_reboot')['checks']['different_boot_after_reboot'] == 'gap'
    with pytest.raises(HostAcceptanceError):
        verify(lab.dir)


def test_no_reuse_of_checkpoint_or_symlink(tmp_path):
    lab = Lab(tmp_path)
    lab.capture('baseline')
    with pytest.raises(HostAcceptanceError, match='new absolute'):
        lab.capture('baseline')
    link = tmp_path/'evidence-link'
    link.symlink_to(lab.dir, target_is_directory=True)
    with pytest.raises(HostAcceptanceError):
        capture(phase='post_restart', directory=link, sensor_id='sensor-01',
                port=8000, token='v' * 48, system_name='Linux')


def test_modified_or_missing_previous_evidence_aborts(tmp_path):
    lab = Lab(tmp_path)
    lab.capture('baseline')
    file = lab.dir / 'baseline.json'
    file.write_text(file.read_text().replace('"status":"pass"', '"status":"gap"'))
    lab.restart()
    with pytest.raises(HostAcceptanceError):
        lab.capture('post_restart')
    assert not (lab.dir/'post_restart.json').exists()


def test_nonprivate_evidence_directory_rejected(tmp_path):
    lab = Lab(tmp_path)
    lab.capture('baseline')
    lab.dir.chmod(0o755)
    lab.restart()
    with pytest.raises(HostAcceptanceError):
        lab.capture('post_restart')


def test_integrity_and_service_gaps_never_pass(tmp_path):
    lab = Lab(tmp_path)
    lab.anchored = False
    result = lab.capture('baseline')
    assert result['status'] == 'gap'
    assert result['checks']['authenticated_event_integrity'] == 'gap'
    other = Lab(tmp_path/'other')
    # Use an existing writable parent to exercise service gap independently.
    (tmp_path/'other').mkdir()
    other.healthy = False
    result = other.capture('baseline')
    assert result['status'] == 'gap'


def test_systemctl_instance_rejects_invalid_and_fixed_nonprivileged_command():
    calls = []
    def valid(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=(
            'InvocationID=' + 'a' * 32 + '\nId=sentinel-ssh-collector.service\n'))
    assert read_invocation(valid) == 'a' * 32
    command, arguments = calls[0]
    assert command[0] == '/usr/bin/systemctl' and command[-1] == 'sentinel-ssh-collector.service'
    assert arguments['timeout'] == 5 and not any(x in command for x in ('restart','stop','start'))
    for output in ('Id=other.service\nInvocationID=' + 'a'*32,
                   'Id=sentinel-ssh-collector.service\nInvocationID=garbage',
                   'Id=sentinel-ssh-collector.service\nId=sentinel-ssh-collector.service'):
        with pytest.raises(HostAcceptanceError):
            read_invocation(lambda *a, **k: SimpleNamespace(returncode=0, stdout=output))


def test_coverage_parser_validates_activity_fields_without_breaking_legacy_fixtures():
    from test_coverage_probe import sample
    old = assess(sample('healthy','explicit'))
    assert old.sensor_activity == ()
    current = sample('healthy','explicit')
    current['sensors'][0].update(event_count=10,heartbeat_count=23)
    assert assess(current).sensor_activity == (('lab-one',10,23),)
    for counts in ({'event_count': -1, 'heartbeat_count': 3},
                   {'event_count': True, 'heartbeat_count': 1},
                   {'event_count': 4},
                   {'event_count': 2**64, 'heartbeat_count': 1}):
        changed = sample('healthy','explicit')
        changed['sensors'][0].update(counts)
        with pytest.raises(CoverageProbeError):
            assess(changed)


def test_cli_does_not_leak_credential_on_failure(tmp_path, monkeypatch, capsys):
    from scripts import qualify_linux_recovery as cli
    from sentinel.coverage_probe import CoverageProbeError
    monkeypatch.setattr(cli, 'read_private_token', lambda _: 'TopSecret' * 6)
    def failed(**kwargs):
        raise HostAcceptanceError('TopSecret' * 6)
    monkeypatch.setattr(cli, 'capture', failed)
    code = cli.main(['--phase','baseline','--evidence-dir',str(tmp_path/'evidence'),
                     '--sensor-id','sensor-01','--token-file','/private/viewer.token'])
    output = capsys.readouterr()
    assert code == 1 and 'TopSecret' not in output.out + output.err
    assert 'SENTINEL HOST QUALIFICATION UNKNOWN' in output.err
