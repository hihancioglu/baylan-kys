"""Add file and ownership fields to documents

Revision ID: 0010
Revises: 0009
Create Date: 2024-05-18 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    columns = {col["name"] for col in inspector.get_columns("documents")}

    if "doc_key" in columns and "file_key" not in columns:
        op.alter_column("documents", "doc_key", new_column_name="file_key")

    if "rev_no" not in columns:
        op.add_column("documents", sa.Column("rev_no", sa.Integer(), nullable=True))

    if "mime" not in columns:
        op.add_column("documents", sa.Column("mime", sa.String(), nullable=True))

    if "owner_id" not in columns:
        op.add_column("documents", sa.Column("owner_id", sa.Integer(), nullable=True))
        op.create_foreign_key(
            "fk_documents_owner_id_users", "documents", "users", ["owner_id"], ["id"]
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    columns = {col["name"] for col in inspector.get_columns("documents")}

    if "owner_id" in columns:
        op.drop_constraint(
            "fk_documents_owner_id_users", "documents", type_="foreignkey"
        )
        op.drop_column("documents", "owner_id")

    if "mime" in columns:
        op.drop_column("documents", "mime")

    if "rev_no" in columns:
        op.drop_column("documents", "rev_no")

    if "file_key" in columns and "doc_key" not in columns:
        op.alter_column("documents", "file_key", new_column_name="doc_key")
