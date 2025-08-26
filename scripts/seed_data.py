"""Seed default roles and admin user."""

from portal.models import Role, RoleEnum, User, SessionLocal


def seed_roles(session) -> None:
    """Ensure all default roles exist."""
    for role in RoleEnum:
        if not session.query(Role).filter_by(name=role.value).first():
            session.add(Role(name=role.value))


def seed_admin_user(session) -> None:
    """Create default admin user with quality_admin role."""
    admin = session.query(User).filter_by(username="admin").first()
    if not admin:
        admin = User(username="admin", email="admin@example.com")
        qa_role = session.query(Role).filter_by(name=RoleEnum.QUALITY_ADMIN.value).first()
        if qa_role:
            admin.roles.append(qa_role)
        session.add(admin)


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
