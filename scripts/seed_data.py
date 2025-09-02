"""Seed default roles and create an initial admin user.

The default admin user's username and email can be configured via the
``INITIAL_ADMIN_USERNAME`` and ``INITIAL_ADMIN_EMAIL`` environment
variables.  If the user already exists it will simply be granted the
``quality_admin`` role.
"""

import os

"""Utilities to seed the database with initial roles and an admin user."""


def _get_models():
    """Import and return the models module lazily.

    Importing inside a function avoids issues where different parts of the
    application reload the ``models`` module, which can result in multiple
    engine instances pointing at different databases. By fetching the module at
    call time we always operate on the currently active engine used by the
    tests or application.
    """

    from portal import models

    return models


def seed_roles(session, models) -> None:
    """Ensure all default roles exist."""
    for role in models.RoleEnum:
        if not session.query(models.Role).filter_by(name=role.value).first():
            session.add(models.Role(name=role.value))


def seed_admin_user(session, models) -> None:
    """Create initial admin user and ensure it has ``quality_admin`` role."""

    username = os.getenv("INITIAL_ADMIN_USERNAME", "admin")
    email = os.getenv("INITIAL_ADMIN_EMAIL", f"{username}@example.com")

    admin = session.query(models.User).filter_by(username=username).first()
    if not admin:
        admin = models.User(username=username, email=email)
        session.add(admin)

    qa_role = session.query(models.Role).filter_by(name=models.RoleEnum.QUALITY_ADMIN.value).first()
    if qa_role and qa_role not in admin.roles:
        admin.roles.append(qa_role)


def seed() -> None:
    """Create tables if needed and seed default data."""

    models = _get_models()

    # Ensure all tables exist before attempting to seed data.
    models.Base.metadata.create_all(bind=models.engine)

    session = models.SessionLocal()
    try:
        seed_roles(session, models)
        seed_admin_user(session, models)
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    seed()
