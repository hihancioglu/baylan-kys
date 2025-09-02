"""Add checkout/checkin/override permissions to document_permissions

Revision ID: 0020
Revises: 0019
Create Date: 2025-09-02

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_permissions")]
    if "can_checkout" not in columns:
        op.add_column(
            "document_permissions",
            sa.Column("can_checkout", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        op.alter_column("document_permissions", "can_checkout", server_default=None)
    if "can_checkin" not in columns:
        op.add_column(
            "document_permissions",
            sa.Column("can_checkin", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        op.alter_column("document_permissions", "can_checkin", server_default=None)
    if "can_override" not in columns:
        op.add_column(
            "document_permissions",
            sa.Column("can_override", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        op.alter_column("document_permissions", "can_override", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_permissions")]
    if "can_override" in columns:
        op.drop_column("document_permissions", "can_override")
    if "can_checkin" in columns:
        op.drop_column("document_permissions", "can_checkin")
    if "can_checkout" in columns:
        op.drop_column("document_permissions", "can_checkout")
