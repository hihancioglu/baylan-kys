"""Add endpoint column to audit_logs

Revision ID: 0005
Revises: 0004
Create Date: 2025-08-18 05:55:11

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("endpoint", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_logs", "endpoint")

