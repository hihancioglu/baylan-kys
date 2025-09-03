"""Add uploaded_by to document_revisions

Revision ID: 0021
Revises: 0020
Create Date: 2025-09-09

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_revisions")]
    if "uploaded_by" not in columns:
        op.add_column(
            "document_revisions",
            sa.Column("uploaded_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("document_revisions")]
    if "uploaded_by" in columns:
        op.drop_column("document_revisions", "uploaded_by")
