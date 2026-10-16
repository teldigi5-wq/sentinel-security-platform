"""Serialize audit authorship and anchor recorded chain tail within this database.

Revision ID: 0002_audit_head
Revises: 0001_initial
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_audit_head"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("audit_heads",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("last_hash", sa.String(64), nullable=False),
        sa.Column("entry_count", sa.Integer, nullable=False))
    conn = op.get_bind()
    records = sa.table("audit_records", sa.column("id", sa.Integer),
        sa.column("previous_hash", sa.String), sa.column("entry_hash", sa.String))
    previous = "0" * 64
    count = 0
    # Refuse to seed a visibly forked or broken legacy audit chain.
    for row in conn.execute(sa.select(records.c.previous_hash, records.c.entry_hash).order_by(records.c.id)):
        if row.previous_hash != previous or not isinstance(row.entry_hash, str) or len(row.entry_hash) != 64:
            raise RuntimeError("Legacy audit linkage invalid; do not upgrade until investigated")
        previous, count = row.entry_hash, count + 1
    heads = sa.table("audit_heads", sa.column("id", sa.Integer), sa.column("last_hash", sa.String), sa.column("entry_count", sa.Integer))
    conn.execute(sa.insert(heads).values(id=1, last_hash=previous, entry_count=count))


def downgrade():
    raise RuntimeError("Sentinel does not support destructive schema downgrades; restore a verified backup")
