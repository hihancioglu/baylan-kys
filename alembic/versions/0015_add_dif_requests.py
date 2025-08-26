"""Add dif requests table

Revision ID: 0015
Revises: 0014
Create Date: 2025-09-07

"""

from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_type WHERE typname = 'dif_request_status'
            ) THEN
                CREATE TYPE dif_request_status AS ENUM (
                    'new',
                    'in_review',
                    'approved',
                    'rejected',
                    'implemented'
                );
            END IF;
        END$$;
        """
    )
    status = sa.Enum(
        "new",
        "in_review",
        "approved",
        "rejected",
        "implemented",
        name="dif_request_status",
        create_type=False,
    )
    op.create_table(
        "dif_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("requester_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("impact", sa.String(), nullable=True),
        sa.Column("priority", sa.String(), nullable=True),
        sa.Column("status", status, nullable=False, server_default="new"),
        sa.Column("related_doc_id", sa.Integer(), sa.ForeignKey("documents.id"), nullable=True),
        sa.Column("attachment_key", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("dif_requests")
    op.execute("DROP TYPE IF EXISTS dif_request_status")
