"""Create standards table and seed data

Revision ID: 0009
Revises: 0008
Create Date: 2025-02-16 00:00:00

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "standards",
        sa.Column("code", sa.String(), primary_key=True),
        sa.Column("description", sa.String(), nullable=True),
    )

    standards_table = sa.table(
        "standards",
        sa.column("code", sa.String()),
        sa.column("description", sa.String()),
    )

    op.bulk_insert(
        standards_table,
        [
            {"code": "ISO9001", "description": "ISO 9001"},
            {"code": "ISO27001", "description": "ISO 27001"},
            {"code": "ISO14001", "description": "ISO 14001"},
        ],
    )

    op.create_foreign_key(
        "fk_document_standards_standard_code_standards",
        "document_standards",
        "standards",
        ["standard_code"],
        ["code"],
    )

    op.execute(
        """
        INSERT INTO document_standards (doc_id, standard_code)
        SELECT d.id, d.standard_code
        FROM documents d
        WHERE d.standard_code IS NOT NULL
          AND NOT EXISTS (
                SELECT 1 FROM document_standards ds
                WHERE ds.doc_id = d.id AND ds.standard_code = d.standard_code
          )
        """
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_document_standards_standard_code_standards",
        "document_standards",
        type_="foreignkey",
    )
    op.drop_table("standards")

