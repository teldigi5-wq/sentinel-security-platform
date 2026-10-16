"""Admission control must fail closed without hiding existing integrity failures."""
from threading import Event, Thread
import pytest
from sentinel.integrity_scan_guard import IntegrityScanGuard, IntegrityScanBusy, IntegrityScanRateLimited
from test_api import client_for, auth


def test_rolling_window_expiry():
    now = [100.0]
    gate = IntegrityScanGuard(limit=2, window_seconds=60, clock=lambda: now[0])
    for _ in range(2):
        with gate.permit():
            pass
    with pytest.raises(IntegrityScanRateLimited):
        with gate.permit():
            pass
    now[0] = 160.0
    with gate.permit():
        pass


def test_concurrent_scan_rejected_without_sticking_gate():
    gate = IntegrityScanGuard()
    start, release, completed = Event(), Event(), Event()
    def worker():
        with gate.permit():
            start.set()
            release.wait(timeout=3)
        completed.set()
    thread = Thread(target=worker)
    thread.start()
    try:
        assert start.wait(timeout=3)
        with pytest.raises(IntegrityScanBusy):
            with gate.permit():
                pass
    finally:
        release.set()
        thread.join(timeout=3)
    assert completed.is_set()
    with gate.permit():
        pass


def test_error_releases_slot_but_consumes_budget():
    gate = IntegrityScanGuard(limit=1)
    with pytest.raises(ZeroDivisionError):
        with gate.permit():
            1 / 0
    with pytest.raises(IntegrityScanRateLimited):
        with gate.permit():
            pass


def test_auth_status_and_admin_integrity_share_budget(tmp_path):
    client, _ = client_for(tmp_path)
    for i in range(12):
        route = '/api/v1/audit/status' if i % 2 == 0 else '/api/v1/audit/integrity'
        response = client.get(route, headers=auth())
        assert response.status_code == 200, response.text
    limited = client.get('/api/v1/audit/status', headers=auth())
    assert limited.status_code == 429
    assert limited.headers['retry-after'] == '60'
    assert limited.headers['cache-control'] == 'no-store'
    assert limited.json() == {'detail': 'Integrity verification rate limited'}
    assert client.get('/api/v1/audit/status').status_code == 401
    assert client.get('/api/v1/health').status_code == 200


def test_new_app_has_new_budget(tmp_path):
    client, _ = client_for(tmp_path)
    for _ in range(12):
        assert client.get('/api/v1/audit/status', headers=auth()).status_code == 200
    assert client.get('/api/v1/audit/status', headers=auth()).status_code == 429
    other, _ = client_for(tmp_path)
    assert other.get('/api/v1/audit/status', headers=auth()).status_code == 200
