"""Minimal normalized evidence and alert schema."""
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class SensorNonce(Base):
    __tablename__ = "sensor_nonces"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sensor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(80), nullable=False)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("sensor_id", "nonce", name="uq_sensor_nonce"),)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sensor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (Index("idx_events_action_ip_time", "action", "source_ip", "observed_at"),)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    explanation: Mapped[str] = mapped_column(String(800), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(100), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"), nullable=False)
    event_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_events.id"), nullable=False)
    __table_args__ = (UniqueConstraint("alert_id", "event_id", name="uq_alert_event"),)


class AuditRecord(Base):
    __tablename__ = "audit_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    actor: Mapped[str] = mapped_column(String(96), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    resource: Mapped[str] = mapped_column(String(140), nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AlertDecision(Base):
    """Operator incident state changes, stored independently from the mutable alert row."""
    __tablename__ = "alert_decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"), nullable=False)
    previous_state: Mapped[str] = mapped_column(String(20), nullable=False)
    new_state: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(String(300), nullable=False)
    actor: Mapped[str] = mapped_column(String(96), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (Index("idx_decisions_alert_time", "alert_id", "decided_at"),)


class AuditHead(Base):
    """Single serialized tail pointer (not an independent immutable audit anchor)."""
    __tablename__ = "audit_heads"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
