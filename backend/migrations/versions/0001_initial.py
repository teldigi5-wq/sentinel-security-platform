"""Legacy v0.4 schema, reproduced as explicit versioned DDL.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("sensor_nonces",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("sensor_id", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(80), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("sensor_id", "nonce", name="uq_sensor_nonce"))
    op.create_table("security_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("sensor_id", sa.String(64), nullable=False),
        sa.Column("asset_id", sa.String(100), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("idx_events_action_ip_time", "security_events", ["action", "source_ip", "observed_at"])
    op.create_table("alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(200), nullable=False, unique=True),
        sa.Column("severity", sa.String(12), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("explanation", sa.String(800), nullable=False),
        sa.Column("asset_id", sa.String(100), nullable=False),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_count", sa.Integer, nullable=False))
    op.create_table("audit_records",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(96), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource", sa.String(140), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False))
    op.create_table("alert_evidence",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id"), nullable=False),
        sa.Column("event_id", sa.String(36), sa.ForeignKey("security_events.id"), nullable=False),
        sa.UniqueConstraint("alert_id", "event_id", name="uq_alert_event"))
    op.create_table("alert_decisions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id"), nullable=False),
        sa.Column("previous_state", sa.String(20), nullable=False),
        sa.Column("new_state", sa.String(20), nullable=False),
        sa.Column("reason", sa.String(300), nullable=False),
        sa.Column("actor", sa.String(96), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("idx_decisions_alert_time", "alert_decisions", ["alert_id", "decided_at"])


def downgrade():
    raise RuntimeError("Sentinel does not support destructive schema downgrades; restore a verified backup")
