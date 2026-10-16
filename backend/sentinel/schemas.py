"""Strict event contract; no arbitrary metadata or attacker-controlled commands."""
from datetime import datetime
from enum import Enum
from typing import Literal
from ipaddress import ip_address
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Category(str, Enum):
    authentication = "authentication"
    network = "network"
    endpoint = "endpoint"


class Action(str, Enum):
    auth_failure = "auth_failure"
    auth_success = "auth_success"
    network_denied = "network_denied"
    malware_detected = "malware_detected"
    integrity_change = "integrity_change"
    privilege_escalation_denied = "privilege_escalation_denied"


ALLOWED_ACTIONS = {
    Category.authentication: {Action.auth_failure, Action.auth_success},
    Category.network: {Action.network_denied},
    Category.endpoint: {Action.malware_detected, Action.integrity_change, Action.privilege_escalation_denied},
}


class IncomingEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    asset_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._:-]+$")
    category: Category
    action: Action
    source_ip: str | None = Field(default=None, max_length=45)
    observed_at: datetime

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        return str(ip_address(value)) if value is not None else None

    @field_validator("observed_at")
    @classmethod
    def require_utc_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include timezone information")
        return value

    @field_validator("action")
    @classmethod
    def no_opaque_action(cls, value: Action) -> Action:
        return value

    def check_pair(self) -> None:
        if self.action not in ALLOWED_ACTIONS[self.category]:
            raise ValueError("Category and action are inconsistent")
        if self.action in (Action.auth_failure, Action.network_denied) and not self.source_ip:
            raise ValueError("source_ip is required for network and authentication failure events")


class SensorHeartbeat(BaseModel):
    """Heartbeats contain no telemetry or arbitrary instructions."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    asset_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9._:-]+$")


class TriageRequest(BaseModel):
    """Fail-closed alert triage contract; no externally supplied operator identity."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expected_state: Literal["open", "investigating", "resolved"]
    new_state: Literal["open", "investigating", "resolved"]
    reason: str = Field(min_length=8, max_length=300)

    @field_validator("reason")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("Reason must not contain control characters")
        return value
