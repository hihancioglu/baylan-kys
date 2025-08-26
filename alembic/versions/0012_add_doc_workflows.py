"""add doc workflows table

Revision ID: 0012
Revises: 0011
Create Date: 2025-02-18 00:00:00
"""

from alembic import op
import sqlalchemy as sa
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
    state_enum = postgresql.ENUM(
        "draft",
        "review",
        "approve",
        "published",
        "obsolete",
        name="doc_workflow_state",
        create_type=False,
    )
    op.create_table(
        "doc_workflows",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.Integer(), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("state", state_enum, nullable=False, server_default="draft"),
        sa.Column("current_step", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("documents", sa.Column("workflow_id", sa.Integer(), nullable=True))
    op.create_foreign_key(None, "documents", "doc_workflows", ["workflow_id"], ["id"])


def downgrade() -> None:
    op.drop_constraint(None, "documents", type_="foreignkey")
    op.drop_column("documents", "workflow_id")
    op.drop_table("doc_workflows")
    op.execute("DROP TYPE IF EXISTS doc_workflow_state")
