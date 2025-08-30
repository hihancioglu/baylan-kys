"""Add file_key column to document_revisions

Revision ID: 0017
Revises: 0016
Create Date: 2025-09-08

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_revisions")]
    if "file_key" not in columns:
        op.add_column(
            "document_revisions",
            sa.Column("file_key", sa.String(), nullable=False, server_default=""),
        )
        op.alter_column("document_revisions", "file_key", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_revisions")]
    if "file_key" in columns:
        op.drop_column("document_revisions", "file_key")
