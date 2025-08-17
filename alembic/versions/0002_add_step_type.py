"""Add step_type to workflow steps

Revision ID: 0002
Revises: 0001
Create Date: 2024-05-27 00:00:00

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    step_type = sa.Enum("review", "approval", name="workflow_step_type")
    step_type.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "workflow_steps",
        sa.Column("step_type", step_type, nullable=False, server_default="review"),
    )


def downgrade() -> None:
    op.drop_column("workflow_steps", "step_type")
    step_type = sa.Enum("review", "approval", name="workflow_step_type")
    step_type.drop(op.get_bind(), checkfirst=True)
