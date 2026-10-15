"""Prints locally generated secrets. Store them securely; never commit output."""
import json
import secrets

print("SENTINEL_OPERATOR_TOKEN=" + secrets.token_urlsafe(48))
print("SENTINEL_AUDIT_KEY=" + secrets.token_urlsafe(48))
print("SENTINEL_SENSOR_KEYS='" + json.dumps({"lab-sensor-1": secrets.token_urlsafe(48)}) + "'")
