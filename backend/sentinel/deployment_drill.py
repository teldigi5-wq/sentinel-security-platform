"""Isolated collector-to-API recovery drill; never touches an installed service.

The drill uses private temporary log/database/cursor files and FastAPI TestClient.
Its results are fixture qualifications, NOT evidence of real-host/systemd operation.
No log contents, credentials, private paths, or source IPs enter the report.
"""
from __future__ import annotations

from datetime import timedelta
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import tempfile
import time

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .app import create_app
from .collectors.linux_ssh import CollectorError, process_file
from .database import migrate
from .models import SensorStatus, utcnow
from .settings import Settings

_SENSOR = "drill-sensor"
_ASSET = "drill-host"
# Synthetic fixture secrets, never suitable for production.
_KEY = "fixture-only-" + "k" * 48
_OPERATOR = "fixture-only-" + "o" * 48
_AUDIT = "fixture-only-" + "a" * 48


def _auth_headers(raw: bytes, nonce: str) -> dict[str, str]:
    stamp = str(int(time.time()))
    message = f"{_SENSOR}\n{stamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
    digest = hmac.new(_KEY.encode(), message, hashlib.sha256).hexdigest()
    return {"X-Sentinel-Sensor": _SENSOR, "X-Sentinel-Timestamp": stamp,
            "X-Sentinel-Nonce": nonce, "X-Sentinel-Signature": digest}


def _auth_failure_line() -> bytes:
    # Data stays in ephemeral fixture files; only IP is normalized by collector.
    return (b"Oct 16 12:00:00 host sshd[531]: Failed password for invalid user fixture "
            b"from 198.51.100.42 port 4444 ssh2\n")


def execute() -> dict[str, object]:
    """Exercise delivery, replay-recovery, rotate, heartbeat, stale/recover, audit.

    All phases run against the real FastAPI router and migrated isolated SQLite,
    but no real TCP socket, systemd daemon, privileged access or host logs.
    """
    checks: list[dict[str, str]] = []
    event_samples = 0

    def check(name: str, condition: bool) -> None:
        checks.append({"id": name, "result": "pass" if condition else "fail"})
        if not condition:
            # Fail closed; report only authored phase names, no raw exception.
            raise CollectorError("Isolated qualification phase failed")

    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-drill-") as directory:
            root = Path(directory)
            log = root / "auth.log"
            cursor_dir = root / "state"
            cursor_dir.mkdir(mode=0o700)
            cursor = cursor_dir / "ssh-cursor.json"
            log.write_bytes(_auth_failure_line() * 3)
            log.chmod(0o600)
            database_url = f"sqlite:///{root / 'isolated.db'}"
            migrate(database_url)
            settings = Settings(database_url=database_url, operator_token=_OPERATOR,
                                audit_key=_AUDIT, sensor_keys={_SENSOR: _KEY},
                                sensor_assets={_SENSOR: _ASSET},
                                frontend_origins=("http://localhost:3000",))
            with TestClient(create_app(settings)) as client:
                viewer = {"Authorization": f"Bearer {_OPERATOR}"}

                def deliver(raw: bytes, nonce: str) -> int:
                    reply = client.post("/api/v1/events", content=raw,
                                        headers=_auth_headers(raw, nonce))
                    if reply.status_code not in (202, 409):
                        raise CollectorError("Isolated event delivery rejected")
                    return reply.status_code

                def poll(send=deliver, *, initial=False) -> tuple[int, int]:
                    return process_file(source=log, state_path=cursor, asset_id=_ASSET,
                                        sensor_key=_KEY, start_at_end=initial, send=send)

                check("initial_no_backfill", poll(initial=True) == (0, 0))
                check("no_historical_alerts", client.get("/api/v1/alerts", headers=viewer).json() == [])

                with log.open("ab") as stream:
                    stream.write(_auth_failure_line() * 5)
                inspected, accepted = poll()
                event_samples += accepted
                check("signed_log_ingestion", (inspected, accepted) == (5, 5))
                check("restart_cursor_idempotent", poll() == (0, 0))
                alerts = client.get("/api/v1/alerts", headers=viewer).json()
                check("detection_alert_and_evidence", len(alerts) == 1
                      and alerts[0]["rule_id"] == "auth-failure-burst-v1"
                      and alerts[0]["evidence_count"] == 5)

                # A successful upstream POST followed by a lost ACK: the saved
                # cursor is behind. Retried delivery reuses the SAME nonce and
                # 409 replay response, which is safe only for this exact position.
                with log.open("ab") as stream:
                    stream.write(_auth_failure_line())
                attempts: list[tuple[str, int]] = []
                def lost_ack(raw: bytes, nonce: str) -> None:
                    status = deliver(raw, nonce)
                    attempts.append((nonce, status))
                    raise CollectorError("Fixture simulates ACK loss")
                failed = False
                try:
                    poll(lost_ack)
                except CollectorError:
                    failed = True
                check("ack_loss_detected", failed and len(attempts) == 1 and attempts[0][1] == 202)
                def retry(raw: bytes, nonce: str) -> None:
                    attempts.append((nonce, deliver(raw, nonce)))
                check("deterministic_nonce_retry", poll(retry) == (1, 1)
                      and len(attempts) == 2 and attempts[0][0] == attempts[1][0]
                      and attempts[1][1] == 409)
                event_samples += 1
                check("no_duplicate_after_retry", client.get("/api/v1/overview",headers=viewer).json()["events"] == 6)

                log.rename(root / "auth.log.1")
                log.write_bytes(_auth_failure_line())
                log.chmod(0o600)
                check("rotation_detected", poll() == (1, 1))
                event_samples += 1
                check("rotation_does_not_replay", poll() == (0, 0))

                def heartbeat() -> int:
                    body = json.dumps({"asset_id": _ASSET}, separators=(",", ":")).encode()
                    result = client.post("/api/v1/sensors/heartbeat", content=body,
                                         headers=_auth_headers(body, secrets.token_hex(16)))
                    return result.status_code
                check("signed_heartbeat", heartbeat() == 202)
                coverage = client.get("/api/v1/sensors",headers=viewer).json()
                check("healthy_coverage", coverage["sensors"][0]["status"] == "healthy")

                # Artificial database clock shift simulates outage only. It is NOT
                # evidence of a real 4-minute wait or systemd restart.
                engine = create_engine(database_url)
                try:
                    with Session(engine) as session:
                        status = session.get(SensorStatus, _SENSOR)
                        if status is None:
                            raise CollectorError("Missing sensor row")
                        status.last_seen_at = utcnow() - timedelta(minutes=4)
                        session.commit()
                finally:
                    engine.dispose()
                check("simulated_outage_detected", client.get("/api/v1/sensors",headers=viewer)
                      .json()["sensors"][0]["status"] == "stale")
                check("heartbeat_recovers_coverage", heartbeat() == 202
                      and client.get("/api/v1/sensors",headers=viewer).json()["sensors"][0]["status"] == "healthy")
                check("audit_chain_valid", client.get("/api/v1/audit/integrity",headers=viewer)
                      .json()["valid"] is True)
                check("expected_event_count", client.get("/api/v1/overview",headers=viewer)
                      .json()["events"] == event_samples == 7)
    except Exception:
        # Do not leak filesystem locations, secrets or raw log data through
        # evidence. A failed drill must remain a failed qualification gate.
        if not checks or checks[-1]["result"] == "pass":
            checks.append({"id": "unexpected_failure", "result": "fail"})

    return {"schema": "sentinel-isolated-linux-recovery-drill-v1",
            "scope": "isolated-synthetic-fixture-only",
            "all_passed": bool(checks) and all(x["result"] == "pass" for x in checks),
            "checks": checks,
            "event_samples": event_samples,
            "host_certified": False,
            "limits": ["no real systemd restart or reboot", "no installed host logs",
                       "no TCP network measurement", "outage simulated via test database clock"]}
