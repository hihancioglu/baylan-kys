"""Add file and ownership fields to documents

Revision ID: 0010
Revises: 0009_create_standards_table
Create Date: 2024-05-18 00:00:00
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0010"
down_revision = "0009_create_standards_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("documents", "doc_key", new_column_name="file_key")
    op.add_column("documents", sa.Column("rev_no", sa.Integer(), nullable=True))
    op.add_column("documents", sa.Column("mime", sa.String(), nullable=True))
    op.add_column("documents", sa.Column("owner_id", sa.Integer(), nullable=True))
    op.create_foreign_key(None, "documents", "users", ["owner_id"], ["id"])


def downgrade() -> None:
    op.drop_constraint(None, "documents", type_="foreignkey")
    op.drop_column("documents", "owner_id")
    op.drop_column("documents", "mime")
    op.drop_column("documents", "rev_no")
    op.alter_column("documents", "file_key", new_column_name="doc_key")
