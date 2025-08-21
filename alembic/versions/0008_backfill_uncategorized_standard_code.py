"""Backfill Uncategorized standard code

Revision ID: 0008
Revises: 0007
Create Date: 2025-02-15 00:00:00

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE documents SET standard_code='Uncategorized' WHERE standard_code IS NULL")


def downgrade() -> None:
    op.execute("UPDATE documents SET standard_code=NULL WHERE standard_code='Uncategorized'")
