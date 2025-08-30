import os
import os
import sys
import importlib
from pathlib import Path
import pytest

# Ensure application modules are importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))

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
def client(monkeypatch):
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["quality_admin"]
    monkeypatch.setattr(app_module, "log_action", lambda *a, **kw: None)
    yield client, models_module
    models_module.SessionLocal.remove()


def test_create_role_standard_scope(client):
    client_app, models = client
    resp = client_app.post(
        "/roles", json={"role": "auditor", "standard_scope": "ISO9001"}
    )
    assert resp.status_code == 200
    db = models.SessionLocal()
    try:
        role = db.query(models.Role).filter_by(name="auditor").one()
        assert role.standard_scope == "ISO9001"
    finally:
        db.close()


def test_create_role_invalid_standard_scope(client):
    client_app, _ = client
    resp = client_app.post(
        "/roles", json={"role": "bad", "standard_scope": "INVALID"}
    )
    assert resp.status_code == 400
