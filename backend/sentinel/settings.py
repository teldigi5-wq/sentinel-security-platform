"""Validated settings. No credentials are bundled or silently defaulted."""
from dataclasses import dataclass
import json
import os
from urllib.parse import urlparse


@dataclass(frozen=True)
class Settings:
    database_url: str
    operator_token: str
    sensor_keys: dict[str, str]
    audit_key: str
    frontend_origins: tuple[str, ...]


def load_settings() -> Settings:
    operator = os.getenv("SENTINEL_OPERATOR_TOKEN", "")
    audit = os.getenv("SENTINEL_AUDIT_KEY", "")
    if len(operator) < 32 or len(audit) < 32:
        raise RuntimeError("Set strong SENTINEL_OPERATOR_TOKEN and SENTINEL_AUDIT_KEY (minimum 32 characters each)")
    try:
        sensor_keys = json.loads(os.getenv("SENTINEL_SENSOR_KEYS", "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("SENTINEL_SENSOR_KEYS must be a JSON object") from exc
    if not isinstance(sensor_keys, dict) or not sensor_keys or any(
        not isinstance(k, str) or not k.isascii() or not 1 <= len(k) <= 64 or
        not all(ch.isalnum() or ch in "_-" for ch in k) or
        not isinstance(v, str) or len(v) < 32 for k, v in sensor_keys.items()
    ):
        raise RuntimeError("SENTINEL_SENSOR_KEYS must map safe sensor IDs to secrets of at least 32 characters")
    origins = tuple(x.strip() for x in os.getenv("SENTINEL_FRONTEND_ORIGINS", "http://localhost:3000").split(",") if x.strip())
    for origin in origins:
        parsed = urlparse(origin)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise RuntimeError("Invalid frontend origin: " + origin)
    return Settings(
        database_url=os.getenv("SENTINEL_DATABASE_URL", "sqlite:///./sentinel.db"),
        operator_token=operator,
        sensor_keys=sensor_keys,
        audit_key=audit,
        frontend_origins=origins,
    )
