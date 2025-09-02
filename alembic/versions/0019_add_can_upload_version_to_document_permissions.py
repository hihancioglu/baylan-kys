"""Add can_upload_version to document_permissions

Revision ID: 0019
Revises: 0018
Create Date: 2025-09-01

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_permissions")]
    if "can_upload_version" not in columns:
        op.add_column(
            "document_permissions",
            sa.Column(
                "can_upload_version", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
        )
        op.alter_column("document_permissions", "can_upload_version", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_permissions")]
    if "can_upload_version" in columns:
        op.drop_column("document_permissions", "can_upload_version")
