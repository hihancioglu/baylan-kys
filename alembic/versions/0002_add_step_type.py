"""Add step_type to workflow steps

Revision ID: 0002
Revises: 0001
Create Date: 2024-05-27 00:00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    step_type = sa.Enum("review", "approval", name="workflow_step_type")
    bind = op.get_bind()
    step_type.create(bind, checkfirst=True)
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("workflow_steps")]
    if "step_type" not in columns:
        op.add_column(
            "workflow_steps",
            sa.Column("step_type", step_type, nullable=False, server_default="review"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("workflow_steps")]
    if "step_type" in columns:
        op.drop_column("workflow_steps", "step_type")
    step_type = sa.Enum("review", "approval", name="workflow_step_type")
    step_type.drop(bind, checkfirst=True)
