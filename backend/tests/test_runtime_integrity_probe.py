"""Runtime audit status is a minimal least-privilege integrity signal."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from sentinel.audit import append_audit
from sentinel.integrity_probe import ASSURANCE, IntegrityProbeError, assess, fetch_integrity
from sentinel.models import AuditRecord, SecurityEvent
from test_api import AUDIT, auth, client_for, post_event


def test_authenticated_viewer_only_minimal_status(tmp_path):
    client, _ = client_for(tmp_path)
    path = '/api/v1/audit/status'
    assert client.get(path).status_code == 401
    assert client.get(path, headers={'Authorization': 'Bearer invalid'}).status_code == 401
    empty = client.get(path, headers=auth())
    assert empty.status_code == 200
    assert empty.json() == {"state": "empty", "valid": True, "has_events": False, "assurance": ASSURANCE}
    assert post_event(client).status_code == 202
    valid = client.get(path, headers=auth())
    assert valid.json() == {"state": "anchored", "valid": True, "has_events": True, "assurance": ASSURANCE}
    assert 'source_ip' not in valid.text and 'operator' not in valid.text
    assert valid.headers['cache-control'] == 'no-store'


def test_altered_event_is_runtime_gap_without_restart(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        event = session.scalar(select(SecurityEvent))
        event.source_ip = '203.0.113.40'
        session.commit()
    engine.dispose()
    response = client.get('/api/v1/audit/status', headers=auth())
    assert response.status_code == 200
    assert response.json()['state'] == 'integrity_failed'
    assert response.json()['valid'] is False


def test_changed_audit_is_runtime_gap_without_restart(tmp_path):
    client, settings = client_for(tmp_path)
    assert post_event(client).status_code == 202
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        record = session.scalar(select(AuditRecord))
        record.actor = 'unauthorized-edit'
        session.commit()
    engine.dispose()
    assert client.get('/api/v1/audit/status', headers=auth()).json()['state'] == 'integrity_failed'


def test_old_unanchored_events_never_report_clear(tmp_path):
    client, settings = client_for(tmp_path)
    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        event = SecurityEvent(id=str(uuid.uuid4()), sensor_id='lab-one', asset_id='workstation-1',
                              category='authentication', action='auth_success', source_ip=None,
                              observed_at=datetime.now(timezone.utc))
        session.add(event)
        session.flush()
        append_audit(session, AUDIT, actor='sensor:lab-one', action='event.ingested', resource=event.id)
        session.commit()
    engine.dispose()
    assert client.get('/api/v1/audit/status', headers=auth()).json()['state'] == 'partial_legacy'


@pytest.mark.parametrize('sample', [
    {}, {"state": "anchored", "valid": True, "has_events": True},
    {"state": [], "valid": True, "has_events": True, "assurance": ASSURANCE},
    {"state": "anchored", "valid": True, "has_events": False, "assurance": ASSURANCE},
    {"state": "anchored", "valid": 1, "has_events": True, "assurance": ASSURANCE},
    {"state": "integrity_failed", "valid": True, "has_events": True, "assurance": ASSURANCE},
    {"state": "partial_legacy", "valid": True, "has_events": False, "assurance": ASSURANCE},
    {"state": "empty", "valid": True, "has_events": True, "assurance": ASSURANCE},
    {"state": "anchored", "valid": True, "has_events": True, "assurance": "host protected"},
])
def test_invalid_or_contradictory_responses_are_unknown(sample):
    with pytest.raises(IntegrityProbeError):
        assess(sample)


@contextmanager
def stub_server(response_body: bytes, *, status: int = 200, mime: str = 'application/json'):
    seen: list[tuple[str, str]] = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get('Authorization', '')))
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.end_headers()
            self.wfile.write(response_body)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, seen
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_actual_loopback_http_and_readonly_bearer():
    token = 'V' * 48
    body = json.dumps({"state": "anchored", "valid": True, "has_events": True, "assurance": ASSURANCE}).encode()
    with stub_server(body) as (port, seen):
        result = fetch_integrity(port=port, token=token)
    assert result.clear
    assert result.summary()['host_certified'] is False
    assert seen == [('/api/v1/audit/status', 'Bearer ' + token)]


@pytest.mark.parametrize('body,status,mime', [
    (b'{}', 200, 'application/json'),
    (b'{broken', 200, 'application/json'),
    (b'{"state":"anchored"}' * 300, 200, 'application/json'),
    (b'{}', 401, 'application/json'),
    (b'{}', 302, 'application/json'),
    (b'{}', 200, 'text/html'),
])
def test_unavailable_and_untrusted_http_fail_unknown(body,status,mime):
    with stub_server(body, status=status, mime=mime) as (port, _):
        with pytest.raises(IntegrityProbeError):
            fetch_integrity(port=port, token='t' * 48)


def test_invalid_port_and_token_do_not_initiate_network():
    for port in (0, -1, 65536, True, '8000'):
        with pytest.raises(IntegrityProbeError):
            fetch_integrity(port=port, token='t' * 48)
    with pytest.raises(IntegrityProbeError):
        fetch_integrity(port=8000, token='short')


def test_cli_exit_semantics_without_secret_output(monkeypatch, capsys):
    from scripts import check_audit_integrity as cli
    from sentinel.integrity_probe import IntegrityAssessment
    monkeypatch.setattr(cli, 'read_private_token', lambda _: 'T' * 48)
    for state, valid, has, expected in (
        ('anchored', True, True, 0),
        ('partial_legacy', True, True, 2),
        ('empty', True, False, 2),
        ('integrity_failed', False, True, 2),
    ):
        monkeypatch.setattr(cli, 'fetch_integrity', lambda **kw: IntegrityAssessment(state, valid, has))
        assert cli.main(['--token-file', '/private/viewer', '--json']) == expected
        output = capsys.readouterr().out
        assert 'T' * 48 not in output
        assert 'host_certified' in output and 'false' in output
    def fail(**_):
        raise IntegrityProbeError('bad actor token T' * 10)
    monkeypatch.setattr(cli, 'fetch_integrity', fail)
    assert cli.main(['--token-file', '/private/viewer', '--json']) == 1
    output = capsys.readouterr().err
    assert output.strip() == 'SENTINEL AUDIT UNKNOWN'


def test_viewer_can_check_status_but_cannot_access_admin_audit(tmp_path):
    from test_operator_rbac import configured_client, headers
    client, _ = configured_client(tmp_path)
    viewer = headers('auditor')
    status = client.get('/api/v1/audit/status', headers=viewer)
    assert status.status_code == 200 and status.json()['state'] == 'empty'
    assert client.get('/api/v1/audit/integrity', headers=viewer).status_code == 403
    assert client.get('/api/v1/audit/integrity', headers=headers('chief-admin')).status_code == 200


def test_monitor_propagates_database_unavailability_as_unknown(tmp_path):
    client, settings = client_for(tmp_path)
    from sqlalchemy import create_engine, text
    engine = create_engine(settings.database_url)
    with engine.begin() as connection:
        connection.execute(text('DROP TABLE audit_records'))
    engine.dispose()
    response = client.get('/api/v1/audit/status', headers=auth())
    assert response.status_code == 503
    assert response.json() == {'detail': 'Integrity state unavailable'}
