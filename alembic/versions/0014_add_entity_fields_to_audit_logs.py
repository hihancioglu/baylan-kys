"""Add entity fields to audit logs

Revision ID: 0014
Revises: 0013
Create Date: 2025-08-19

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {c["name"]: c for c in inspector.get_columns("audit_logs")}
    if "entity_type" not in columns:
        op.add_column("audit_logs", sa.Column("entity_type", sa.String(), nullable=True))
    if "entity_id" not in columns:
        op.add_column("audit_logs", sa.Column("entity_id", sa.Integer(), nullable=True))
    if "payload" not in columns:
        op.add_column("audit_logs", sa.Column("payload", sa.JSON(), nullable=True))
    if "created_at" in columns and "at" not in columns:
        op.alter_column("audit_logs", "created_at", new_column_name="at")
    user_col = columns.get("user_id")
    if user_col and not user_col["nullable"]:
        op.alter_column("audit_logs", "user_id", existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {c["name"]: c for c in inspector.get_columns("audit_logs")}
    if "user_id" in columns and columns["user_id"]["nullable"]:
        op.alter_column("audit_logs", "user_id", existing_type=sa.Integer(), nullable=False)
    if "at" in columns and "created_at" not in columns:
        op.alter_column("audit_logs", "at", new_column_name="created_at")
    if "payload" in columns:
        op.drop_column("audit_logs", "payload")
    if "entity_id" in columns:
        op.drop_column("audit_logs", "entity_id")
    if "entity_type" in columns:
        op.drop_column("audit_logs", "entity_type")
