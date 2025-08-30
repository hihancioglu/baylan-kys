import os
import sys
import importlib
from pathlib import Path
import pytest

# Ensure application modules are importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))

# Set required environment variables
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET_MAIN", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")


@pytest.fixture(autouse=True)
def iso_standards_env(monkeypatch):
    monkeypatch.setenv(
        "ISO_STANDARDS",
        "ISO9001:ISO 9001,ISO27001:ISO 27001,ISO14001:ISO 14001",
    )


@pytest.fixture()
def client():
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module.app.test_client(), models_module


def test_documents_respect_standard_scope(client):
    client_app, models = client
    models.seed_documents()
    session = models.SessionLocal()
    try:
        role_iso9001 = models.Role(name="iso9001_role", standard_scope="ISO9001")
        role_iso27001 = models.Role(name="iso27001_role", standard_scope="ISO27001")
        role_all = models.Role(name="all_role", standard_scope="ALL")
        session.add_all([role_iso9001, role_iso27001, role_all])
        session.commit()
        user1 = models.User(username="u1", email="u1@example.com")
        user1.roles.append(role_iso9001)
        user2 = models.User(username="u2", email="u2@example.com")
        user2.roles.append(role_iso27001)
        user3 = models.User(username="u3", email="u3@example.com")
        user3.roles.append(role_all)
        session.add_all([user1, user2, user3])
        session.commit()
        user1_id, user2_id, user3_id = user1.id, user2.id, user3.id
        role_iso9001_name = role_iso9001.name
        role_iso27001_name = role_iso27001.name
        role_all_name = role_all.name
    finally:
        session.close()

    with client_app.session_transaction() as sess:
        sess["user"] = {"id": user1_id}
        sess["roles"] = ["reader", role_iso9001_name]
    resp = client_app.get("/documents")
    assert resp.status_code == 200
    data = resp.get_data(as_text=True)
    assert "Seeded Document 1" in data
    assert "Seeded Document 2" in data
    assert "Seeded Document 3" not in data

    with client_app.session_transaction() as sess:
        sess["user"] = {"id": user2_id}
        sess["roles"] = ["reader", role_iso27001_name]
    resp = client_app.get("/documents")
    assert resp.status_code == 200
    data = resp.get_data(as_text=True)
    assert "Seeded Document 2" in data
    assert "Seeded Document 1" not in data
    assert "Seeded Document 3" not in data

    with client_app.session_transaction() as sess:
        sess["user"] = {"id": user3_id}
        sess["roles"] = ["reader", role_all_name]
    resp = client_app.get("/documents")
    assert resp.status_code == 200
    data = resp.get_data(as_text=True)
    assert "Seeded Document 1" in data
    assert "Seeded Document 2" in data
    assert "Seeded Document 3" in data
