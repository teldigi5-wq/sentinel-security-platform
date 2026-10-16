"""Seed a fresh, private SQLite store with genuine signed ingestion for browser CI.

Only for an isolated local GitHub runner. Never use with production credentials or DBs.
The result contains disposable secrets; keep it 0600 and never upload as an artifact.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import time

from fastapi.testclient import TestClient

from sentinel.app import create_app
from sentinel.database import migrate
from sentinel.settings import OperatorIdentity, Settings

SENSOR = "fixture-sensor"
ASSET = "fixture-host"
SOURCE_IP = "192.0.2.42"  # RFC 5737 TEST-NET-1, not real host data


def _sign(sensor_key: str, sensor_id: str, body: bytes) -> dict[str, str]:
    stamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    content_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{sensor_id}\n{stamp}\n{nonce}\n{content_hash}".encode()
    return {
        "X-Sentinel-Sensor": sensor_id,
        "X-Sentinel-Timestamp": stamp,
        "X-Sentinel-Nonce": nonce,
        "X-Sentinel-Signature": hmac.new(sensor_key.encode(), canonical, hashlib.sha256).hexdigest(),
    }


def prepare(directory: Path) -> dict:
    """Generate a disposable backend database and secret file in a private folder."""
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError("Fixture directory must be an existing absolute private directory")
    folder = directory.stat()
    if os.name == "posix" and (folder.st_uid != os.getuid() or folder.st_mode & 0o077):
        raise ValueError("Fixture directory must be owned by caller and mode 0700")
    db = directory / "browser.sqlite3"
    output = directory / "fixture.json"
    if db.exists() or output.exists() or db.is_symlink() or output.is_symlink():
        raise ValueError("Fixture files already exist; refusing overwrite")
    viewer = secrets.token_urlsafe(48)
    admin = secrets.token_urlsafe(48)
    audit_key = secrets.token_urlsafe(48)
    sensor_key = secrets.token_urlsafe(48)
    identities = (
        OperatorIdentity("fixture-viewer", "viewer", hashlib.sha256(viewer.encode()).hexdigest()),
        OperatorIdentity("fixture-admin", "admin", hashlib.sha256(admin.encode()).hexdigest()),
    )
    db_url = f"sqlite:///{db}"
    config = Settings(
        database_url=db_url,
        operator_token="",
        sensor_keys={SENSOR: sensor_key},
        sensor_assets={SENSOR: ASSET},
        audit_key=audit_key,
        frontend_origins=("http://127.0.0.1:3100",),
        operators=identities,
    )
    migrate(db_url)
    # Real FastAPI routes, HMAC verification, nonce database, detection and audit.
    with TestClient(create_app(config)) as client:
        for _ in range(5):
            event = {"asset_id": ASSET, "category": "authentication", "action": "auth_failure",
                     "source_ip": SOURCE_IP, "observed_at": datetime.now(timezone.utc).isoformat()}
            body = json.dumps(event, separators=(",", ":")).encode()
            response = client.post("/api/v1/events", content=body, headers=_sign(sensor_key, SENSOR, body))
            if response.status_code != 202:
                raise RuntimeError("Signed browser fixture ingestion failed")
        heartbeat = json.dumps({"asset_id": ASSET}).encode()
        response = client.post("/api/v1/sensors/heartbeat", content=heartbeat,
                               headers=_sign(sensor_key, SENSOR, heartbeat))
        if response.status_code != 202:
            raise RuntimeError("Signed browser fixture heartbeat failed")
        viewer_headers = {"Authorization": "Bearer " + viewer}
        admin_headers = {"Authorization": "Bearer " + admin}
        overview = client.get("/api/v1/overview", headers=viewer_headers)
        alerts = client.get("/api/v1/alerts", headers=viewer_headers)
        audit = client.get("/api/v1/audit/integrity", headers=admin_headers)
        if (overview.status_code != 200 or overview.json()["events"] != 5
                or alerts.status_code != 200 or len(alerts.json()) != 1
                or alerts.json()[0]["evidence_count"] != 5
                or audit.status_code != 200 or not audit.json()["valid"]):
            raise RuntimeError("Browser fixture failed genuine backend acceptance checks")
        if (client.get("/api/v1/audit/integrity", headers=viewer_headers).status_code != 403
                or client.get("/api/v1/overview").status_code != 401):
            raise RuntimeError("Browser fixture role separation failed")
    # No secrets in stdout, CLI args, CI artifacts or repo. This file is ephemeral.
    values = {"viewer": viewer, "admin": admin, "invalid": "invalid-" + "x"*42,
              "expectedEvents": 5, "expectedAlertEvidence": 5, "expectedAuditRecords": audit.json()["records"],
              "env": {"SENTINEL_DATABASE_URL": db_url, "SENTINEL_AUDIT_KEY": audit_key,
                      "SENTINEL_AUTH_MODE": "static", "SENTINEL_SENSOR_KEYS": json.dumps({SENSOR: sensor_key}),
                      "SENTINEL_SENSOR_ASSETS": json.dumps({SENSOR: ASSET}),
                      "SENTINEL_FRONTEND_ORIGINS": "http://127.0.0.1:3100",
                      "SENTINEL_OPERATORS": json.dumps({identity.operator_id: {
                          "role": identity.role, "token_sha256": identity.token_sha256
                      } for identity in identities})}}
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(values, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {"events": 5, "alerts": 1, "signed_heartbeat": True, "fixture_only": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Create ephemeral locally signed browser CI data")
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.directory)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())