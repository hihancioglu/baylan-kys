"""add required_role and due_at to workflow steps

Revision ID: 0013
Revises: 0012
Create Date: 2025-03-01 00:00:00
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("workflow_steps", sa.Column("required_role", sa.String(), nullable=True))
    op.add_column("workflow_steps", sa.Column("due_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("workflow_steps", "due_at")
    op.drop_column("workflow_steps", "required_role")
