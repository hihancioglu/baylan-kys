"""Add endpoint column to audit_logs

Revision ID: 0005
Revises: 0004
Create Date: 2025-08-18 05:55:11

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

def upgrade() -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    columns = [col["name"] for col in inspector.get_columns("audit_logs")]

    if "endpoint" not in columns:
        op.add_column("audit_logs", sa.Column("endpoint", sa.String(), nullable=True))


def downgrade() -> None:
    connection = op.get_bind()
    inspector = inspect(connection)
    columns = [col["name"] for col in inspector.get_columns("audit_logs")]

    if "endpoint" in columns:
        op.drop_column("audit_logs", "endpoint")

