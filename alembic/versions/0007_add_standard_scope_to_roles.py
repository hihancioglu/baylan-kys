"""Add standard_scope to roles

Revision ID: 0007
Revises: 0006
Create Date: 2025-02-14 00:00:00

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add standard_scope column if it does not already exist."""

    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [col["name"] for col in inspector.get_columns("roles")]
    if "standard_scope" not in columns:
        op.add_column(
            "roles",
            sa.Column(
                "standard_scope",
                sa.String(),
                nullable=False,
                server_default="ALL",
            ),
        )


def downgrade() -> None:
    """Drop standard_scope column if it exists."""

    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [col["name"] for col in inspector.get_columns("roles")]
    if "standard_scope" in columns:
        op.drop_column("roles", "standard_scope")
