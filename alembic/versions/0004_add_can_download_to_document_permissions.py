"""Add can_download column to document_permissions

Revision ID: 0004
Revises: 0003
Create Date: 2025-08-18 05:55:11

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "document_permissions",
        sa.Column("can_download", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.alter_column("document_permissions", "can_download", server_default=None)


def downgrade() -> None:
    op.drop_column("document_permissions", "can_download")
