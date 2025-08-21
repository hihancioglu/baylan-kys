import os
import sys
import importlib
from pathlib import Path

import pytest

# Required environment variables for app initialization
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET_MAIN", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture(autouse=True)
def iso_standards_env(monkeypatch):
    monkeypatch.setenv(
        "ISO_STANDARDS",
        "ISO9001:ISO 9001,ISO27001:ISO 27001,ISO14001:ISO 14001",
    )


@pytest.fixture()
def app_models():
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module, models_module


@pytest.fixture()
def admin_client(app_models):
    app_module, _ = app_models
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["quality_admin"]
    return client


def test_document_standards_page_lists_docs(app_models, admin_client):
    app_module, models = app_models
    models.seed_documents()
    resp = admin_client.get("/admin/document-standards")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Seeded Document 1" in body


def test_admin_updates_document_standard(app_models, admin_client):
    app_module, models = app_models
    models.seed_documents()
    session_db = models.SessionLocal()
    doc = session_db.query(models.Document).filter_by(code="SD1").first()
    session_db.close()

    codes = list(app_module.STANDARD_MAP.keys())
    new_standard = codes[1] if len(codes) > 1 else codes[0]

    resp = admin_client.post(
        f"/admin/document-standards/{doc.id}", json={"standard": new_standard}
    )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    session_db = models.SessionLocal()
    updated = session_db.get(models.Document, doc.id)
    assert updated.standard_code == new_standard
    assert [s.standard_code for s in updated.standards] == [new_standard]
    session_db.close()
