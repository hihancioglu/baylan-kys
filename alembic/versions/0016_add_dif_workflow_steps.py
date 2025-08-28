"""Add dif workflow steps table

Revision ID: 0016
Revises: 0015
Create Date: 2025-09-07

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("dif_workflow_steps"):
        op.create_table(
            "dif_workflow_steps",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "dif_id", sa.Integer(), sa.ForeignKey("dif_requests.id"), nullable=False
            ),
            sa.Column("role", sa.String(), nullable=False),
            sa.Column("step_order", sa.Integer(), nullable=False),
            sa.Column("sla_hours", sa.Integer(), nullable=True),
            sa.Column(
                "status", sa.String(), nullable=False, server_default="Pending"
            ),
            sa.Column("acted_at", sa.DateTime(), nullable=True),
            sa.Column("comment", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if inspector.has_table("dif_workflow_steps"):
        op.drop_table("dif_workflow_steps")
