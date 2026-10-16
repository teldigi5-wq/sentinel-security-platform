"""Validated settings. No credentials are bundled or silently defaulted."""
from dataclasses import dataclass, field
import re
import json
import os
from urllib.parse import urlparse


@dataclass(frozen=True)
class OperatorIdentity:
    operator_id: str
    role: str
    token_sha256: str


@dataclass(frozen=True)
class Settings:
    database_url: str
    operator_token: str
    sensor_keys: dict[str, str]
    audit_key: str
    frontend_origins: tuple[str, ...]
    operators: tuple[OperatorIdentity, ...] = field(default_factory=tuple)
    auth_mode: str = "static"


def load_settings() -> Settings:
    operator = os.getenv("SENTINEL_OPERATOR_TOKEN", "")
    audit = os.getenv("SENTINEL_AUDIT_KEY", "")
    configured_operators = os.getenv("SENTINEL_OPERATORS")
    auth_mode = os.getenv("SENTINEL_AUTH_MODE", "static")
    if auth_mode not in ("static", "database"):
        raise RuntimeError("SENTINEL_AUTH_MODE must be static or database")
    if auth_mode == "database" and (operator or configured_operators is not None):
        raise RuntimeError("Database auth mode forbids legacy/static operator credentials")
    if len(audit) < 32 or (auth_mode == "static" and configured_operators is None and len(operator) < 32):
        raise RuntimeError("Set a strong audit key and either individual operators or a legacy operator token")
    operators: list[OperatorIdentity] = []
    if configured_operators is not None:
        try:
            definitions = json.loads(configured_operators)
        except json.JSONDecodeError as exc:
            raise RuntimeError("SENTINEL_OPERATORS must be a JSON object") from exc
        if not isinstance(definitions, dict) or not 1 <= len(definitions) <= 32:
            raise RuntimeError("SENTINEL_OPERATORS needs 1 to 32 individually enrolled operators")
        fingerprints = set()
        for operator_id, definition in definitions.items():
            if not isinstance(operator_id, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", operator_id):
                raise RuntimeError("Invalid operator ID in SENTINEL_OPERATORS")
            if not isinstance(definition, dict) or set(definition) != {"role", "token_sha256"}:
                raise RuntimeError("Each operator needs exactly role and token_sha256")
            role, digest = definition["role"], definition["token_sha256"]
            if role not in ("viewer", "analyst", "admin") or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise RuntimeError("Invalid operator role or lowercase SHA-256 token digest")
            if digest in fingerprints:
                raise RuntimeError("Duplicate operator token digest is forbidden")
            fingerprints.add(digest)
            operators.append(OperatorIdentity(operator_id, role, digest))
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
        operators=tuple(operators),
        auth_mode=auth_mode,
    )
