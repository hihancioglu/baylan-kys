import runpy

from portal import models


def test_seed_creates_roles_and_admin():
    runpy.run_path("scripts/seed_data.py", run_name="__main__")

    session = models.SessionLocal()
    try:
        roles = {r.name for r in session.query(models.Role).all()}
        expected = {r.value for r in models.RoleEnum}
        assert expected <= roles

        admin = session.query(models.User).filter_by(username="admin").first()
        assert admin is not None
    finally:
        session.close()
