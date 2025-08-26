"""Add entity fields to audit logs

Revision ID: 0014
Revises: 0013
Create Date: 2025-08-19

"""
from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("entity_type", sa.String(), nullable=True))
    op.add_column("audit_logs", sa.Column("entity_id", sa.Integer(), nullable=True))
    op.add_column("audit_logs", sa.Column("payload", sa.JSON(), nullable=True))
    op.alter_column("audit_logs", "created_at", new_column_name="at")
    op.alter_column("audit_logs", "user_id", existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    op.alter_column("audit_logs", "user_id", existing_type=sa.Integer(), nullable=False)
    op.alter_column("audit_logs", "at", new_column_name="created_at")
    op.drop_column("audit_logs", "payload")
    op.drop_column("audit_logs", "entity_id")
    op.drop_column("audit_logs", "entity_type")
