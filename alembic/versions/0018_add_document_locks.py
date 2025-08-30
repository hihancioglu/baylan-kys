"""Add lock fields to documents

Revision ID: 0018
Revises: 0017
Create Date: 2025-09-09

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("documents")]
    if "locked_by" not in columns:
        op.add_column("documents", sa.Column("locked_by", sa.Integer(), nullable=True))
        op.create_foreign_key(
            "documents_locked_by_fkey", "documents", "users", ["locked_by"], ["id"]
        )
    if "lock_expires_at" not in columns:
        op.add_column("documents", sa.Column("lock_expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("documents")]
    if "lock_expires_at" in columns:
        op.drop_column("documents", "lock_expires_at")
    if "locked_by" in columns:
        op.drop_constraint("documents_locked_by_fkey", "documents", type_="foreignkey")
        op.drop_column("documents", "locked_by")
