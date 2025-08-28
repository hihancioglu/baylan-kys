"""Add can_download column to document_permissions

Revision ID: 0004
Revises: 0003
Create Date: 2025-08-18 05:55:11

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_permissions")]
    if "can_download" not in columns:
        op.add_column(
            "document_permissions",
            sa.Column(
                "can_download", sa.Boolean(), nullable=False, server_default=sa.true()
            ),
        )
        op.alter_column("document_permissions", "can_download", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_permissions")]
    if "can_download" in columns:
        op.drop_column("document_permissions", "can_download")
