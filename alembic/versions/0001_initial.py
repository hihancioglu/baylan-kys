"""Initial database schema

Revision ID: 0001
Revises: 
Create Date: 2023-01-01 00:00:00

"""

from alembic import op
import sqlalchemy as sa
from portal.models import Base

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind)
