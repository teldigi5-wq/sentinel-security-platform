"""Sends 5 AUTH_FAILURE events using the documented signed sensor protocol."""
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sensor_id = os.getenv("SENTINEL_DEMO_SENSOR_ID", "lab-sensor-1")
keys = json.loads(os.environ["SENTINEL_SENSOR_KEYS"])
secret = keys[sensor_id]
url = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000") + "/api/v1/events"
for attempt in range(1, 6):
    event = {"asset_id": "lab-workstation-01", "category": "authentication", "action": "auth_failure",
             "source_ip": "198.51.100.42", "observed_at": datetime.now(timezone.utc).isoformat()}
    raw = json.dumps(event, separators=(",", ":")).encode()
    stamp, nonce = str(int(time.time())), secrets.token_hex(16)
    canonical = f"{sensor_id}\n{stamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
    signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    headers = {"Content-Type": "application/json", "X-Sentinel-Sensor": sensor_id,
               "X-Sentinel-Timestamp": stamp, "X-Sentinel-Nonce": nonce, "X-Sentinel-Signature": signature}
    request = urllib.request.Request(url, data=raw, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            print(attempt, response.status, response.read().decode())
    except urllib.error.HTTPError as exc:
        print("ERROR", exc.code, exc.read().decode(), file=sys.stderr)
        sys.exit(1)
