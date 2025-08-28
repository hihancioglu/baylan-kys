"""Add standard_code to documents and create document_standards table

Revision ID: 0006
Revises: 0005
Create Date: 2025-02-13 00:00:00

This migration previously attempted to add the ``standard_code`` column to
``documents`` without checking if the column already existed.  When the
column had been manually created, running the migration resulted in a
``DuplicateColumn`` error.  The upgrade and downgrade steps now use
SQLAlchemy's reflection facilities to inspect the current schema before
modifying it, avoiding errors if the column or table is already present.

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add the ``standard_code`` column and ``document_standards`` table.

    Uses SQLAlchemy's reflection utilities to guard against applying the
    migration twice.  If the ``standard_code`` column already exists on the
    ``documents`` table, it will not be added again, preventing a database
    error.  The same approach is used for the ``document_standards`` table.
    """

    bind = op.get_bind()
    inspector = sa.inspect(bind)

    document_columns = {col["name"] for col in inspector.get_columns("documents")}
    if "standard_code" not in document_columns:
        op.add_column(
            "documents", sa.Column("standard_code", sa.String(), nullable=True)
        )

    if not inspector.has_table("document_standards"):
        op.create_table(
            "document_standards",
            sa.Column(
                "doc_id", sa.Integer(), sa.ForeignKey("documents.id"), primary_key=True
            ),
            sa.Column("standard_code", sa.String(), primary_key=True),
        )


def downgrade() -> None:
    """Drop ``document_standards`` and the ``standard_code`` column if present."""

    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("document_standards"):
        op.drop_table("document_standards")

    document_columns = {col["name"] for col in inspector.get_columns("documents")}
    if "standard_code" in document_columns:
        op.drop_column("documents", "standard_code")
