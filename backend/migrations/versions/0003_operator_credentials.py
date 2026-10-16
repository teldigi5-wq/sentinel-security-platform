"""Add hashed operator credentials and persistent revocation."""
from alembic import op
import sqlalchemy as sa

revision = "0003_operator_credentials"
down_revision = "0002_audit_head"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "operator_credentials",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("operator_id", sa.String(64), nullable=False),
        sa.Column("role", sa.String(12), nullable=False),
        sa.Column("token_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_operator_credentials_operator", "operator_credentials", ["operator_id"])

def downgrade():
    raise RuntimeError("Destructive downgrade prohibited; restore a verified backup")
