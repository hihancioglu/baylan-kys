"""Add standard_code to documents and create document_standards table

Revision ID: 0006
Revises: 0005
Create Date: 2025-02-13 00:00:00

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("documents", sa.Column("standard_code", sa.String(), nullable=True))
    op.create_table(
        "document_standards",
        sa.Column("doc_id", sa.Integer(), sa.ForeignKey("documents.id"), primary_key=True),
        sa.Column("standard_code", sa.String(), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("document_standards")
    op.drop_column("documents", "standard_code")
