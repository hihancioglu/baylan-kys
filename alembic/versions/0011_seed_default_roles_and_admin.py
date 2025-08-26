"""Seed default roles and admin user

Revision ID: 0011
Revises: 0010
Create Date: 2025-02-17 00:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    roles = [
        "reader",
        "contributor",
        "reviewer",
        "approver",
        "publisher",
        "quality_admin",
        "auditor",
        "survey_admin",
        "complaints_owner",
        "risk_committee",
    ]

    roles_table = sa.table(
        "roles",
        sa.column("name", sa.String()),
        sa.column("standard_scope", sa.String()),
    )
    op.bulk_insert(
        roles_table,
        [{"name": r, "standard_scope": "ALL"} for r in roles],
    )

    users_table = sa.table(
        "users",
        sa.column("username", sa.String()),
        sa.column("email", sa.String()),
    )
    op.bulk_insert(
        users_table,
        [{"username": "admin", "email": "admin@example.com"}],
    )

    op.execute(
        """
        INSERT INTO user_roles (user_id, role_id)
        SELECT u.id, r.id FROM users u, roles r
        WHERE u.username='admin' AND r.name='quality_admin'
        """
    )


def downgrade() -> None:
    op.execute(
        "DELETE FROM user_roles WHERE user_id = (SELECT id FROM users WHERE username='admin')"
    )
    op.execute("DELETE FROM users WHERE username='admin'")
    op.execute(
        "DELETE FROM roles WHERE name IN ('reader','contributor','reviewer','approver','publisher','quality_admin','auditor','survey_admin','complaints_owner','risk_committee')"
    )
