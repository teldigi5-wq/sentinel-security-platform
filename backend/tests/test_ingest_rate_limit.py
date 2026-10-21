"""Authenticated sensor ingest rate guard regressions."""
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sentinel.app import create_app
from sentinel.rate_limit import SensorIngestLimiter
from sentinel.settings import Settings


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
    import pytest
    with pytest.raises(ValueError):
        SensorIngestLimiter(max_events=0)
    with pytest.raises(ValueError):
        SensorIngestLimiter(window_seconds=0)


def test_untrusted_signature_cannot_exhaust_authorized_sensor_quota(tmp_path):
    sensor_secret = "s" * 48
    operator_secret = "o" * 48
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'bounded-events.db'}",
        operator_token=operator_secret,
        audit_key="a" * 48,
        sensor_keys={"lab-one": sensor_secret},
        frontend_origins=("http://localhost:3000",),
    )
    limiter = SensorIngestLimiter(max_events=2)
    client = TestClient(create_app(settings, ingest_limiter=limiter))
    raw = json.dumps({
        "asset_id": "prototype-one", "category": "authentication",
        "action": "auth_failure", "source_ip": "198.51.100.10",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }, separators=(",", ":")).encode()

    def send(*, signed: bool = True):
        nonce = secrets.token_hex(16)
        timestamp = str(int(time.time()))
        canonical = f"lab-one\n{timestamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
        signature = hmac.new(sensor_secret.encode(), canonical, hashlib.sha256).hexdigest()
        return client.post("/api/v1/events", content=raw, headers={
            "X-Sentinel-Sensor": "lab-one",
            "X-Sentinel-Timestamp": timestamp,
            "X-Sentinel-Nonce": nonce,
            "X-Sentinel-Signature": signature if signed else "0" * 64,
        })

    for _ in range(6):
        assert send(signed=False).status_code == 401
    assert send().status_code == 202
    assert send().status_code == 202
    exceeded = send()
    assert exceeded.status_code == 429
    assert exceeded.headers["retry-after"] == "60"
    overview = client.get("/api/v1/overview", headers={"Authorization": f"Bearer {operator_secret}"})
    assert overview.status_code == 200
    assert overview.json()["events"] == 2
