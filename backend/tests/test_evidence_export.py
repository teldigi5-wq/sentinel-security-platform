"""Tamper-resistant and non-destructive export against a real migrated DB."""
from datetime import timedelta
import json
import os

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from sentinel.evidence_export import export_event_evidence, verify_event_export
from sentinel.models import AuditRecord, AlertEvidence, SecurityEvent, utcnow
from test_api import AUDIT, client_for, post_event


def seeded(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    source = tmp_path / 'test.db'
    # Trust actual fixture configuration if its DB filename changes.
    source = __import__('pathlib').Path(settings.database_url.removeprefix('sqlite:///'))
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        event = session.scalar(select(SecurityEvent))
        event.received_at = utcnow() - timedelta(days=40)
        session.commit()
    engine.dispose()
    return source, settings.database_url


def counts(url):
    engine = create_engine(url)
    try:
        with Session(engine) as s:
            return tuple(s.scalar(select(func.count()).select_from(m)) for m in (SecurityEvent, AlertEvidence, AuditRecord))
    finally:
        engine.dispose()


def test_export_round_trip_preserves_source_and_links(tmp_path):
    source, url = seeded(tmp_path)
    before = counts(url)
    directory = tmp_path / 'sealed'
    fields = export_event_evidence(source, directory, AUDIT, older_than_days=30)
    assert fields['events_count'] == 1
    assert fields['schema_revision'] == '0004_sensor_status'
    assert verify_event_export(directory, AUDIT) == fields
    assert counts(url) == before
    rows = [json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    assert len(rows) == 1 and rows[0]['sensor_id'] == 'lab-one'
    if os.name == 'posix':
        assert directory.stat().st_mode & 0o077 == 0
        for file in ('events.jsonl','manifest.json'):
            assert (directory/file).stat().st_mode & 0o077 == 0


def test_wrong_key_rejected_without_output(tmp_path):
    source, _ = seeded(tmp_path)
    with pytest.raises(ValueError, match='integrity|audit|verification'):
        export_event_evidence(source, tmp_path/'bad', 'B'*48)
    assert not (tmp_path/'bad').exists()


def test_payload_tampering_is_detected(tmp_path):
    source, _ = seeded(tmp_path)
    folder = tmp_path/'bundle'
    export_event_evidence(source, folder, AUDIT)
    file = folder/'events.jsonl'
    content = file.read_bytes()
    file.write_bytes(content.replace(b'lab-one', b'lab-two'))
    with pytest.raises(ValueError, match='checksum'):
        verify_event_export(folder, AUDIT)


def test_manifest_tampering_and_wrong_key_are_rejected(tmp_path):
    source, _ = seeded(tmp_path)
    folder = tmp_path/'bundle'
    export_event_evidence(source, folder, AUDIT)
    with pytest.raises(ValueError, match='authentication'):
        verify_event_export(folder, 'B'*48)
    manifest = folder/'manifest.json'
    modified = json.loads(manifest.read_text())
    modified['data']['events_count'] = 900
    manifest.write_text(json.dumps(modified))
    with pytest.raises(ValueError, match='authentication'):
        verify_event_export(folder, AUDIT)


def test_bound_refuses_partial_selection(tmp_path):
    source, url = seeded(tmp_path)
    engine = create_engine(url)
    with Session(engine) as s:
        seed = s.scalar(select(SecurityEvent))
        s.add(SecurityEvent(id='c'*36,sensor_id=seed.sensor_id,asset_id=seed.asset_id,
                            category=seed.category,action=seed.action,source_ip=seed.source_ip,
                            observed_at=seed.observed_at,received_at=seed.received_at))
        s.commit()
    engine.dispose()
    with pytest.raises(ValueError, match='exceed max_events'):
        export_event_evidence(source, tmp_path/'partial', AUDIT, max_events=1)
    assert not (tmp_path/'partial').exists()


def test_fresh_events_not_exported_by_old_observed_timestamp(tmp_path):
    source, url = seeded(tmp_path)
    engine=create_engine(url)
    with Session(engine) as s:
        event=s.scalar(select(SecurityEvent))
        event.received_at=utcnow()
        event.observed_at=utcnow()-timedelta(days=90)
        s.commit()
    engine.dispose()
    result=export_event_evidence(source,tmp_path/'empty',AUDIT,older_than_days=30)
    assert result['events_count']==0
    assert verify_event_export(tmp_path/'empty',AUDIT)==result


def test_reject_overwrite_symlink_and_weak_parameters(tmp_path):
    source, _ = seeded(tmp_path)
    existing=tmp_path/'existing';existing.mkdir()
    with pytest.raises(FileExistsError):
        export_event_evidence(source,existing,AUDIT)
    link=tmp_path/'linked';link.symlink_to(source)
    with pytest.raises(ValueError,match='regular'):
        export_event_evidence(link,tmp_path/'no',AUDIT)
    for value in (True,0,10001):
        with pytest.raises(ValueError,match='max_events'):
            export_event_evidence(source,tmp_path/'no',AUDIT,max_events=value)
    for value in (True,0,3651):
        with pytest.raises(ValueError,match='older_than_days'):
            export_event_evidence(source,tmp_path/'no',AUDIT,older_than_days=value)
    assert not (tmp_path/'no').exists()


def test_private_verifier_blocks_symlink_and_open_directory(tmp_path):
    source, _ = seeded(tmp_path)
    folder=tmp_path/'bundle'
    export_event_evidence(source,folder,AUDIT)
    link=tmp_path/'linked_bundle';link.symlink_to(folder,target_is_directory=True)
    with pytest.raises(ValueError,match='real directory'):
        verify_event_export(link,AUDIT)
    if os.name=='posix':
        folder.chmod(0o755)
        with pytest.raises(ValueError,match='private'):
            verify_event_export(folder,AUDIT)


def test_cli_export_and_verify_without_leaking_raw_events(tmp_path):
    import subprocess
    import sys
    source, _ = seeded(tmp_path)
    bundle = tmp_path / 'cli-bundle'
    env = dict(os.environ, SENTINEL_AUDIT_KEY=AUDIT)
    command = [sys.executable, '-m', 'scripts.export_event_evidence']
    exported = subprocess.run(command + ['export', str(source), str(bundle), '--days', '30'],
                              text=True, capture_output=True, env=env, check=False)
    assert exported.returncode == 0, exported.stderr
    assert json.loads(exported.stdout)['events_count'] == 1
    assert 'lab-one' not in exported.stdout
    checked = subprocess.run(command + ['verify', str(bundle)], text=True,
                             capture_output=True, env=env, check=False)
    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout)['events_sha256'] == json.loads(exported.stdout)['events_sha256']
