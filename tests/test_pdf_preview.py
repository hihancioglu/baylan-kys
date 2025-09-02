import io
import os
import sys
import importlib
from pathlib import Path
from unittest.mock import MagicMock
from types import SimpleNamespace

import pytest
from flask import template_rendered

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models(tmp_path):
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        db_url = f"sqlite:///{Path(tmp_path)/'test.db'}"
    os.environ["DATABASE_URL"] = db_url
    os.environ["STORAGE__TYPE"] = "fs"
    os.environ["STORAGE__FS_PATH"] = str(tmp_path / "files")
    import storage as storage_root
    import portal.storage as portal_storage
    importlib.reload(storage_root)
    importlib.reload(portal_storage)
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.import_module("models")
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    app_module.extract_text = lambda key: ""
    app_module.index_document = lambda doc, content: None
    app_module.notify_mandatory_read = lambda doc, users: None
    pdf_job = importlib.reload(importlib.import_module("pdf_preview_job"))
    import rq_stub
    pdf_job.queue = rq_stub.Queue()
    return app_module, models_module, pdf_job, portal_storage


@pytest.fixture()
def client(app_models):
    app_module, _, _, _ = app_models
    return app_module.app.test_client()


def _login(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["contributor", "reader"]


def test_enqueue_preview_called_on_docx_upload(app_models, client):
    app_module, models, pdf_job, _ = app_models
    _login(client)
    app_module.enqueue_preview = MagicMock()
    storage_root = importlib.import_module("storage")
    storage_root.storage_client.head_object = MagicMock(return_value={})

    first = list(app_module.STANDARD_MAP.keys())[0]
    payload = {
        "code": "DOCX1",
        "title": "Docx",
        "type": "T",
        "department": "Dept",
        "tags": "tag",
        "uploaded_file_key": "upload1",
        "uploaded_file_name": "file.docx",
        "standard": first,
    }
    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 201
    assert app_module.enqueue_preview.called


def test_generate_preview_creates_file_and_view_shows_preview(app_models, client):
    app_module, models, pdf_job, portal_storage = app_models
    _login(client)
    session = models.SessionLocal()
    doc = models.Document(
        doc_key="docs/test.docx",
        title="Test",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    session.add(doc)
    session.commit()
    doc_id = doc.id
    session.close()

    portal_storage.storage_client.put(Key="docs/test.docx", Body=b"data")

    def fake_convert(src, outdir):
        pdf_path = os.path.join(outdir, "test.pdf")
        with open(pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n")
        return pdf_path

    pdf_job.convert_to_pdf = fake_convert
    pdf_job.generate_preview(doc_id, "1.0", "docs/test.docx")

    preview_key = f"previews/{doc_id}/1.0.pdf"
    portal_storage.storage_client.head_object(Key=preview_key)

    captured = {}

    def record(sender, template, context, **extra):
        captured.update(context)

    with template_rendered.connected_to(record, app_module.app):
        resp = client.get(f"/documents/{doc_id}")
    assert resp.status_code == 200
    assert captured["preview"]["type"] == "pdf"


def test_presigned_preview_uses_public_endpoint(monkeypatch):
    monkeypatch.setenv("S3_ENDPOINT", "http://internal:9000")
    monkeypatch.setenv("S3_PUBLIC_ENDPOINT", "https://cdn.example.com")
    monkeypatch.setenv("S3_ACCESS_KEY", "key")
    monkeypatch.setenv("S3_SECRET_KEY", "secret")
    monkeypatch.setenv("S3_BUCKET_MAIN", "main")

    import portal.storage as storage

    class DummyClient:
        def list_buckets(self):
            return {"Buckets": []}

        def create_bucket(self, **kwargs):
            pass

        def put_bucket_versioning(self, **kwargs):
            pass

        def head_object(self, Bucket, Key):
            return {"ContentLength": 1}

        def generate_presigned_url(self, *args, **kwargs):
            return "http://internal:9000/main/previews/test.pdf?X=internal"

    class DummyPublicClient(DummyClient):
        def generate_presigned_url(self, *args, **kwargs):
            return "https://cdn.example.com/main/previews/test.pdf?X=public"

    def client_factory(*args, **kwargs):
        if kwargs.get("endpoint_url") == "https://cdn.example.com":
            return DummyPublicClient()
        return DummyClient()

    monkeypatch.setattr(storage, "boto3", SimpleNamespace(client=client_factory))

    backend = storage.MinIOBackend()
    url = backend.generate_presigned_url("previews/test.pdf")
    assert url == "https://cdn.example.com/main/previews/test.pdf?X=public"
