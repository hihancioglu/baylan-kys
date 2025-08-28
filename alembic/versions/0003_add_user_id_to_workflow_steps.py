"""Add user_id to workflow steps

Revision ID: 0003
Revises: 0002
Create Date: 2024-08-17 00:00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("workflow_steps")]
    if "user_id" not in columns:
        op.add_column(
            "workflow_steps",
            sa.Column("user_id", sa.Integer(), nullable=True),
        )
        op.create_foreign_key(
            None, "workflow_steps", "users", ["user_id"], ["id"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("workflow_steps")]
    if "user_id" in columns:
        op.drop_constraint(None, "workflow_steps", type_="foreignkey")
        op.drop_column("workflow_steps", "user_id")
