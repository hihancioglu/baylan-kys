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
    """Create standards table and seed data in an idempotent fashion."""

    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # Create the table only if it doesn't already exist
    if not inspector.has_table("standards"):
        op.create_table(
            "standards",
            sa.Column("code", sa.String(), primary_key=True),
            sa.Column("description", sa.String(), nullable=True),
        )

    # Seed initial data; ON CONFLICT prevents duplicate rows
    seed_rows = [
        {"code": "ISO9001", "description": "ISO 9001"},
        {"code": "ISO27001", "description": "ISO 27001"},
        {"code": "ISO14001", "description": "ISO 14001"},
    ]
    for row in seed_rows:
        op.execute(
            sa.text(
                "INSERT INTO standards (code, description) "
                "VALUES (:code, :description) "
                "ON CONFLICT (code) DO NOTHING"
            ),
            row,
        )

    # Create the foreign key only if it doesn't already exist
    fk_name = "fk_document_standards_standard_code_standards"
    existing_fks = inspector.get_foreign_keys("document_standards")
    if not any(fk["name"] == fk_name for fk in existing_fks):
        op.create_foreign_key(
            fk_name,
            "document_standards",
            "standards",
            ["standard_code"],
            ["code"],
        )

    # Populate association table for existing documents
    op.execute(
        sa.text(
            """
            INSERT INTO document_standards (doc_id, standard_code)
            SELECT d.id, d.standard_code
            FROM documents d
            JOIN standards s ON s.code = d.standard_code
            WHERE d.standard_code IS NOT NULL
              AND NOT EXISTS (
                    SELECT 1 FROM document_standards ds
                    WHERE ds.doc_id = d.id AND ds.standard_code = d.standard_code
              )
            """
        )
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_document_standards_standard_code_standards",
        "document_standards",
        type_="foreignkey",
    )
    op.drop_table("standards")
