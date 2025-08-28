"""add doc workflows table

Revision ID: 0012
Revises: 0011
Create Date: 2025-02-18 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'doc_workflow_state') THEN
                CREATE TYPE doc_workflow_state AS ENUM (
                    'draft', 'review', 'approve', 'published', 'obsolete'
                );
            END IF;
        END$$;
        """
    )
    bind = op.get_bind()
    inspector = inspect(bind)

    state_enum = postgresql.ENUM(
        "draft",
        "review",
        "approve",
        "published",
        "obsolete",
        name="doc_workflow_state",
        create_type=False,
    )

    # Create the doc_workflows table if it does not already exist
    if "doc_workflows" not in inspector.get_table_names():
        op.create_table(
            "doc_workflows",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "document_id",
                sa.Integer(),
                sa.ForeignKey("documents.id"),
                nullable=False,
            ),
            sa.Column("state", state_enum, nullable=False, server_default="draft"),
            sa.Column("current_step", sa.Integer(), nullable=False, server_default="0"),
        )

    # Add workflow_id column to documents if it does not already exist
    document_columns = [col["name"] for col in inspector.get_columns("documents")]
    if "workflow_id" not in document_columns:
        op.add_column("documents", sa.Column("workflow_id", sa.Integer(), nullable=True))

    # Ensure foreign key from documents.workflow_id to doc_workflows.id exists
    fk_tables = [fk["referred_table"] for fk in inspector.get_foreign_keys("documents")]
    if "doc_workflows" not in fk_tables:
        op.create_foreign_key(
            None, "documents", "doc_workflows", ["workflow_id"], ["id"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    # Drop foreign key constraint if it exists
    for fk in inspector.get_foreign_keys("documents"):
        if fk["referred_table"] == "doc_workflows":
            op.drop_constraint(fk["name"], "documents", type_="foreignkey")

    # Drop workflow_id column if it exists
    document_columns = [col["name"] for col in inspector.get_columns("documents")]
    if "workflow_id" in document_columns:
        op.drop_column("documents", "workflow_id")

    # Drop doc_workflows table if it exists
    if "doc_workflows" in inspector.get_table_names():
        op.drop_table("doc_workflows")

    op.execute("DROP TYPE IF EXISTS doc_workflow_state")
