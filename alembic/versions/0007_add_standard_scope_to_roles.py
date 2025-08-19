"""Add standard_scope to roles

Revision ID: 0007
Revises: 0006
Create Date: 2025-02-14 00:00:00

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
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
    op.drop_column("roles", "standard_scope")
