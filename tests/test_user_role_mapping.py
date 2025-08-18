import os
import importlib
from pathlib import Path
import sys
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

# Make application modules importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def models():
    m = importlib.reload(importlib.import_module("models"))
    yield m
    # ensure session registry is cleaned
    m.SessionLocal.remove()


@pytest.fixture()
def session(models):
    db = models.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_user_role_mapping(models, session):
    m = models
    # create users and roles
    alice = m.User(username="alice")
    bob = m.User(username="bob")
    reader = m.Role(name="reader")
    editor = m.Role(name="editor")
    session.add_all([alice, bob, reader, editor])
    session.commit()

    # assign roles
    alice.roles.append(reader)
    alice.roles.append(editor)
    reader.users.append(bob)
    session.commit()

    # verify bidirectional retrieval
    assert {r.name for r in alice.roles} == {"reader", "editor"}
    assert {u.username for u in reader.users} == {"alice", "bob"}

    # role removal
    alice.roles.remove(reader)
    session.commit()
    assert {r.name for r in alice.roles} == {"editor"}
    assert {u.username for u in reader.users} == {"bob"}

    # uniqueness constraint on association table
    with pytest.raises(IntegrityError):
        session.execute(
            m.user_roles.insert().values(user_id=bob.id, role_id=reader.id)
        )
        session.commit()
    session.rollback()

    # ensure only one mapping exists after failed insert
    result = session.execute(
        select(m.user_roles).where(
            m.user_roles.c.user_id == bob.id,
            m.user_roles.c.role_id == reader.id,
        )
    ).fetchall()
    assert len(result) == 1
