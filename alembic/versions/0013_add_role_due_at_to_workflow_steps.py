"""add required_role and due_at to workflow steps

Revision ID: 0013
Revises: 0012
Create Date: 2025-03-01 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("workflow_steps")]
    if "required_role" not in columns:
        op.add_column(
            "workflow_steps", sa.Column("required_role", sa.String(), nullable=True)
        )
    if "due_at" not in columns:
        op.add_column("workflow_steps", sa.Column("due_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("workflow_steps")]
    if "due_at" in columns:
        op.drop_column("workflow_steps", "due_at")
    if "required_role" in columns:
        op.drop_column("workflow_steps", "required_role")
