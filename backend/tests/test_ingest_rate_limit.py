"""v0.34 authenticated sensor ingest rate guard regressions.

Ported from PR #48 and extended for the v0.33 candidate: the quota covers both
signed routes and replayed nonces must never consume it.
"""
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sentinel.app import create_app
from sentinel.database import migrate
from sentinel.rate_limit import SensorIngestLimiter
from sentinel.settings import Settings

SENSOR_KEY = "s" * 48
OPERATOR = "o" * 48


def test_limiter_bounds_burst_and_resets_on_window_expiry():
    clock = [100.0]
    limiter = SensorIngestLimiter(max_events=2, window_seconds=60, clock=lambda: clock[0])
    assert limiter.allow("sensor-one")
    assert limiter.allow("sensor-one")
    assert not limiter.allow("sensor-one")
    assert limiter.allow("sensor-two")
    clock[0] += 60.01
    assert limiter.allow("sensor-one")


def test_limiter_bounds_identity_state():
    limiter = SensorIngestLimiter(max_events=1, max_sensors=2)
    assert limiter.allow("a")
    assert limiter.allow("b")
    assert limiter.allow("c")
    assert len(limiter._windows) <= 2


def test_limiter_rejects_bad_configuration():
    with pytest.raises(ValueError):
        SensorIngestLimiter(max_events=0)
    with pytest.raises(ValueError):
        SensorIngestLimiter(window_seconds=0)
    with pytest.raises(ValueError):
        SensorIngestLimiter(max_sensors=0)


def _client(tmp_path, limiter):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'bounded-events.db'}",
        operator_token=OPERATOR,
        audit_key="a" * 48,
        sensor_keys={"lab-one": SENSOR_KEY},
        frontend_origins=("http://localhost:3000",),
    )
    migrate(settings.database_url)
    return TestClient(create_app(settings, ingest_limiter=limiter))


def _event():
    return json.dumps({
        "asset_id": "prototype-one", "category": "authentication",
        "action": "auth_failure", "source_ip": "198.51.100.10",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }, separators=(",", ":")).encode()


def _send(client, route="/api/v1/events", raw=None, *, nonce=None, signed=True):
    raw = raw if raw is not None else _event()
    nonce = nonce or secrets.token_hex(16)
    timestamp = str(int(time.time()))
    canonical = f"lab-one\n{timestamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
    signature = hmac.new(SENSOR_KEY.encode(), canonical, hashlib.sha256).hexdigest()
    return client.post(route, content=raw, headers={
        "X-Sentinel-Sensor": "lab-one",
        "X-Sentinel-Timestamp": timestamp,
        "X-Sentinel-Nonce": nonce,
        "X-Sentinel-Signature": signature if signed else "0" * 64,
    })


def _event_count(client):
    overview = client.get("/api/v1/overview", headers={"Authorization": f"Bearer {OPERATOR}"})
    assert overview.status_code == 200
    return overview.json()["events"]


def test_untrusted_signature_cannot_exhaust_authorized_sensor_quota(tmp_path):
    client = _client(tmp_path, SensorIngestLimiter(max_events=2))
    for _ in range(6):
        assert _send(client, signed=False).status_code == 401
    assert _send(client).status_code == 202
    assert _send(client).status_code == 202
    exceeded = _send(client)
    assert exceeded.status_code == 429
    assert exceeded.headers["retry-after"] == "60"
    assert _event_count(client) == 2


def test_replayed_signed_request_cannot_exhaust_sensor_quota(tmp_path):
    """A captured, validly signed request replayed in the skew window must 409
    without consuming the genuine sensor's quota (defect found in PR #48)."""
    client = _client(tmp_path, SensorIngestLimiter(max_events=2))
    raw = _event()
    nonce = secrets.token_hex(16)
    assert _send(client, raw=raw, nonce=nonce).status_code == 202
    for _ in range(10):
        assert _send(client, raw=raw, nonce=nonce).status_code == 409
    assert _send(client).status_code == 202
    assert _send(client).status_code == 429
    assert _event_count(client) == 2


def test_heartbeats_share_the_sensor_quota(tmp_path):
    client = _client(tmp_path, SensorIngestLimiter(max_events=2))
    beat = json.dumps({"asset_id": "prototype-one"}, separators=(",", ":")).encode()
    assert _send(client, "/api/v1/sensors/heartbeat", beat).status_code == 202
    assert _send(client).status_code == 202
    assert _send(client, "/api/v1/sensors/heartbeat", beat).status_code == 429
    assert _send(client).status_code == 429
    assert _event_count(client) == 1


def test_default_limit_admits_existing_synthetic_workloads(tmp_path):
    client = _client(tmp_path, None)
    for _ in range(25):
        assert _send(client).status_code == 202
    assert _event_count(client) == 25
