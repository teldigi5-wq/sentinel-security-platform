"""Isolated synthetic rule evaluation via real signed sensor HTTP endpoints.

NOT an estimate of field detection performance, capture latency, or true attacker
attribution. Each case uses its own migrated ephemeral database and fresh data.
"""
import hashlib
import hmac
import json
import math
import secrets
import statistics
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from .app import create_app
from .database import migrate
from .settings import Settings

_SENSOR = "quality-lab"
_KEY = "test-only-" + "k" * 48
_OP = "test-only-" + "o" * 48
_AUDIT = "test-only-" + "a" * 48

# (case ID, action, count, seconds between events, # source IPs, # assets, expected rule IDs)
# Cases are reviewed synthetic fixtures: their success does not establish the
# false-positive rate for real organizations or unknown attack techniques.
CASES = [
    ("authentication-burst", "auth_failure", 5, 10, 1, 1, ("auth-failure-burst-v1",)),
    ("authentication-under-threshold", "auth_failure", 4, 10, 1, 1, ()),
    ("authentication-distributed-sources", "auth_failure", 5, 10, 5, 1, ()),
    ("authentication-distributed-assets", "auth_failure", 5, 10, 1, 5, ()),
    ("authentication-spaced-out", "auth_failure", 5, 360, 1, 1, ()),
    ("successful-logins", "auth_success", 8, 10, 1, 1, ()),
    ("network-denial-burst", "network_denied", 12, 5, 1, 1, ("network-denial-burst-v1",)),
    ("network-denial-under-threshold", "network_denied", 11, 5, 1, 1, ()),
    ("network-denial-distributed-sources", "network_denied", 12, 5, 3, 1, ()),
    ("network-denial-distributed-assets", "network_denied", 12, 5, 1, 2, ()),
    ("network-denial-spaced-out", "network_denied", 12, 130, 1, 1, ()),
    ("malware-indicator", "malware_detected", 1, 1, 1, 1, ("malware-indicator-v1",)),
    ("privilege-denial", "privilege_escalation_denied", 1, 1, 1, 1, ("privilege-denial-v1",)),
    ("integrity-no-current-rule", "integrity_change", 3, 10, 1, 1, ()),
    ("single-login", "auth_failure", 1, 10, 1, 1, ()),
]

CATEGORIES = {
    "auth_failure": "authentication", "auth_success": "authentication",
    "network_denied": "network", "malware_detected": "endpoint",
    "privilege_escalation_denied": "endpoint", "integrity_change": "endpoint",
}


def _sign(body: bytes, sensor_id: str, sensor_key: str):
    stamp, nonce = str(int(time.time())), secrets.token_hex(16)
    canonical = f"{sensor_id}\n{stamp}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()
    signature = hmac.new(sensor_key.encode(), canonical, hashlib.sha256).hexdigest()
    return {"X-Sentinel-Sensor": sensor_id, "X-Sentinel-Timestamp": stamp,
            "X-Sentinel-Nonce": nonce, "X-Sentinel-Signature": signature}


def _percentile(samples, pct):
    values = sorted(samples)
    return round(values[math.ceil(len(values) * pct / 100) - 1], 3)


def execute(cases=None):
    """Return report. An exact rule-label mismatch is a failed qualification."""
    cases = CASES if cases is None else cases
    if not cases or len(cases) > 100 or len({x[0] for x in cases}) != len(cases):
        raise ValueError("Empty, oversized or duplicate-ID benchmark")
    baseline = datetime.now(timezone.utc) - timedelta(hours=4)
    results, latencies = [], []
    tp = fp = fn = negative = false_positive_cases = 0
    for case_id, action, count, step, source_count, asset_count, expected in cases:
        if action not in CATEGORIES or not (1 <= count <= 100 and 0 <= step <= 3600) or not (1 <= source_count <= 10 and 1 <= asset_count <= 10):
            raise ValueError("Invalid benchmark fixture")
        with tempfile.TemporaryDirectory(prefix="sentinel-quality-") as temp:
            url = f"sqlite:///{Path(temp) / 'case.db'}"
            migrate(url)
            # Preserve sensor identity in multi-asset synthetic fixtures.
            inventory = {f"{_SENSOR}-{i}": f"host-{i}" for i in range(asset_count)}
            keys = {sid: f"{_KEY}-{i}" for i, sid in enumerate(inventory)}
            settings = Settings(database_url=url, operator_token=_OP, audit_key=_AUDIT,
                                sensor_keys=keys, sensor_assets=inventory,
                                frontend_origins=("http://localhost:3000",))
            with TestClient(create_app(settings)) as client:
                for index in range(count):
                    sensor_id = f"{_SENSOR}-{index % asset_count}"
                    evt = {"asset_id": f"host-{index % asset_count}",
                           "category": CATEGORIES[action], "action": action,
                           "observed_at": (baseline + timedelta(seconds=index * step)).isoformat()}
                    if action in ("auth_failure", "network_denied"):
                        evt["source_ip"] = f"198.51.100.{10 + index % source_count}"
                    body = json.dumps(evt, separators=(",", ":")).encode()
                    start = time.perf_counter_ns()
                    response = client.post("/api/v1/events", content=body, headers=_sign(body, sensor_id, keys[sensor_id]))
                    latencies.append((time.perf_counter_ns() - start) / 1_000_000)
                    if response.status_code != 202:
                        raise RuntimeError(f"Signed ingestion failed: {case_id}, HTTP {response.status_code}")
                auth = {"Authorization": "Bearer " + _OP}
                alert_response = client.get("/api/v1/alerts", headers=auth)
                audit_response = client.get("/api/v1/audit/integrity", headers=auth)
                if alert_response.status_code != 200 or audit_response.status_code != 200 or not audit_response.json()["valid"]:
                    raise RuntimeError(f"Evidence validation failed for {case_id}")
                actual = [alert["rule_id"] for alert in alert_response.json()]
                passed = sorted(actual) == sorted(expected)
                tp += len(set(actual) & set(expected))
                fp += len(set(actual) - set(expected))
                fn += len(set(expected) - set(actual))
                if not expected:
                    negative += 1
                    false_positive_cases += bool(actual)
                results.append({"scenario": case_id, "expected": list(expected),
                                "observed": sorted(actual), "passed": passed, "events": count})
    ordered = sorted(latencies)
    return {
        "benchmark": "synthetic-detection-regression-v08",
        "scope": "Synthetic fixture regression ONLY, not field accuracy or production latency",
        "all_passed": all(x["passed"] for x in results),
        "scenarios": len(results),
        "event_samples": len(latencies),
        "rule_label_counts": {"tp": tp, "fp": fp, "fn": fn},
        "synthetic_precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "synthetic_recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "negative_scenario_alert_rate": round(false_positive_cases / negative, 4) if negative else None,
        "testclient_ingestion_latency_ms": {
            "median": round(statistics.median(ordered), 3),
            "p95_nearest_rank": _percentile(ordered, 95)},
        "results": results,
    }
