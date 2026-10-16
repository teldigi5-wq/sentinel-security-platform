"""Persist signed sensor contact for explicit stale/never-seen coverage.

Revision ID: 0004_sensor_status
Revises: 0003_operator_credentials
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_sensor_status"
down_revision = "0003_operator_credentials"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("sensor_status",
        sa.Column("sensor_id", sa.String(64), primary_key=True),
        sa.Column("asset_id", sa.String(100), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_count", sa.Integer, nullable=False),
        sa.Column("heartbeat_count", sa.Integer, nullable=False))

def downgrade():
    raise RuntimeError("Destructive downgrade prohibited; restore verified backup")
