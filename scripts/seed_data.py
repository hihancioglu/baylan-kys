"""Seed default roles and create an initial admin user.

The default admin user's username and email can be configured via the
``INITIAL_ADMIN_USERNAME`` and ``INITIAL_ADMIN_EMAIL`` environment
variables.  If the user already exists it will simply be granted the
``quality_admin`` role.
"""

import os

from portal.models import Role, RoleEnum, SessionLocal, User


def seed_roles(session) -> None:
    """Ensure all default roles exist."""
    for role in RoleEnum:
        if not session.query(Role).filter_by(name=role.value).first():
            session.add(Role(name=role.value))


def seed_admin_user(session) -> None:
    """Create initial admin user and ensure it has ``quality_admin`` role."""

    username = os.getenv("INITIAL_ADMIN_USERNAME", "admin")
    email = os.getenv("INITIAL_ADMIN_EMAIL", f"{username}@example.com")

    admin = session.query(User).filter_by(username=username).first()
    if not admin:
        admin = User(username=username, email=email)
        session.add(admin)

    qa_role = session.query(Role).filter_by(name=RoleEnum.QUALITY_ADMIN.value).first()
    if qa_role and qa_role not in admin.roles:
        admin.roles.append(qa_role)


def seed() -> None:
    session = SessionLocal()
    try:
        seed_roles(session)
        seed_admin_user(session)
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    seed()
