import os
import sys
import importlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET_MAIN", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")
os.environ.setdefault(
    "ISO_STANDARDS",
    "ISO9001:ISO 9001,ISO27001:ISO 27001,ISO14001:ISO 14001",
)

ISO_MAP = dict(item.split(":", 1) for item in os.environ["ISO_STANDARDS"].split(","))
FIRST_STANDARD = list(ISO_MAP.keys())[0]
SECOND_STANDARD = list(ISO_MAP.keys())[1] if len(ISO_MAP) > 1 else FIRST_STANDARD

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models():
    app_module = importlib.import_module("app")
    models_module = importlib.import_module("models")
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module, models_module


@pytest.fixture()
def client(app_models):
    app_module, _ = app_models
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["contributor", "reader"]
    return client


def _mock_env(app_module):
    storage = importlib.import_module("storage")
    storage.storage_client.head_object = MagicMock(return_value={})
    app_module.extract_text = lambda key: "dummy"
    app_module.notify_mandatory_read = lambda doc, users: None
    return storage


def test_create_document_with_standard(app_models, client):
    app_module, models = app_models
    _mock_env(app_module)

    payload = {
        "code": "DOC1",
        "title": "My Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "uploaded_file_key": "abc123",
        "uploaded_file_name": "file.txt",
        "standard": FIRST_STANDARD,
    }

    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["standard"] == FIRST_STANDARD

    session_db = models.SessionLocal()
    doc = session_db.get(models.Document, data["id"])
    assert doc.standard_code == FIRST_STANDARD
    session_db.close()


def test_create_document_invalid_standard(app_models, client):
    app_module, _ = app_models
    _mock_env(app_module)

    payload = {
        "code": "DOC1",
        "title": "My Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "uploaded_file_key": "abc123",
        "uploaded_file_name": "file.txt",
        "standard": "INVALID",
    }

    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 400
    data = resp.get_json()
    assert "standard" in data["errors"]


def test_update_document_standard(app_models, client):
    app_module, models = app_models
    _mock_env(app_module)

    create_payload = {
        "code": "DOC1",
        "title": "My Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "uploaded_file_key": "abc123",
        "uploaded_file_name": "file.txt",
        "standard": FIRST_STANDARD,
    }

    resp = client.post("/api/documents", json=create_payload)
    doc_id = resp.get_json()["id"]

    resp = client.put(f"/api/documents/{doc_id}", json={"standard": SECOND_STANDARD})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["standard"] == SECOND_STANDARD

    session_db = models.SessionLocal()
    doc = session_db.get(models.Document, doc_id)
    assert doc.standard_code == SECOND_STANDARD
    session_db.close()


def test_filter_documents_by_standard(app_models, client):
    _, models = app_models
    models.seed_documents()

    resp = client.get(f"/documents?standard={FIRST_STANDARD}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Seeded Document 1" in body
    assert "Seeded Document 2" in body
    assert "Seeded Document 3" not in body


def test_seed_documents_with_standards(app_models):
    """Seeding helper populates single and multi-standard docs."""
    _, models = app_models
    models.seed_documents()

    session_db = models.SessionLocal()
    docs = {d.code: d for d in session_db.query(models.Document).all()}

    assert [s.standard_code for s in docs["SD1"].standards] == [FIRST_STANDARD]
    assert set(s.standard_code for s in docs["SD2"].standards) == {
        FIRST_STANDARD,
        SECOND_STANDARD,
    }
    assert [s.standard_code for s in docs["SD3"].standards] == [SECOND_STANDARD]
    session_db.close()

