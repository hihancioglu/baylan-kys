"""Add due_at to acknowledgements

Revision ID: 0022
Revises: 0021
Create Date: 2025-09-10

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("acknowledgements")]
    if "due_at" not in columns:
        op.add_column(
            "acknowledgements",
            sa.Column("due_at", sa.DateTime(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("acknowledgements")]
    if "due_at" in columns:
        op.drop_column("acknowledgements", "due_at")

