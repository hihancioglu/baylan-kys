import io
import importlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ["S3_BUCKET_MAIN"] = "local"

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models():
    os.environ["S3_BUCKET_MAIN"] = "local"
    importlib.reload(importlib.import_module("storage"))
    importlib.reload(importlib.import_module("portal.storage"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module, models_module


@pytest.fixture()
def client(app_models):
    app_module, _ = app_models
    return app_module.app.test_client()


def _login(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["contributor"]



def _login_reader(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["reader"]


def _create_doc(models, can_upload=True):

    session = models.SessionLocal()
    role = models.Role(name="r")
    user = models.User(id=1, username="u1")
    user.roles.append(role)
    doc = models.Document(
        file_key="orig.pdf",
        title="Doc",
        status="Published",
        mime="application/pdf",
    )
    session.add_all([role, user, doc])
    session.commit()
    if can_upload is not None:
        perm = models.DocumentPermission(
            role_id=role.id, doc_id=doc.id, can_upload_version=can_upload
        )
        session.add(perm)
        session.commit()
    doc_id = doc.id
    session.close()
    return doc_id


def test_upload_new_version_success(client, app_models):
    app_module, models = app_models
    _login(client)
    doc_id = _create_doc(models)

    storage = importlib.import_module("storage")
    storage.storage_client.put = MagicMock()

    data = {"file": (io.BytesIO(b"data"), "test.pdf"), "notes": "rev1"}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["minor_version"] == 1
    assert storage.storage_client.put.called

    session = models.SessionLocal()
    log = (
        session.query(models.AuditLog)
        .filter_by(doc_id=doc_id, action="version_uploaded")
        .first()
    )
    assert log is not None
    assert log.payload == {
        "version": f"{body['major_version']}.{body['minor_version']}",
        "size": 4,
        "content_type": "application/pdf",
        "note": "rev1",
    }
    rev = session.query(models.DocumentRevision).filter_by(doc_id=doc_id).first()
    assert rev.uploaded_by == 1
    session.close()


def test_upload_new_version_forbidden(client, app_models):
    app_module, models = app_models
    _login_reader(client)
    doc_id = _create_doc(models)

    storage = importlib.import_module("storage")
    storage.storage_client.put = MagicMock()

    data = {"file": (io.BytesIO(b"data"), "test.pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 403

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    assert doc.minor_version == 0
    revs = session.query(models.DocumentRevision).filter_by(doc_id=doc_id).all()
    assert len(revs) == 0
    session.close()
    storage.storage_client.put.assert_not_called()


def test_upload_new_version_invalid_mime(client, app_models):
    app_module, models = app_models
    _login(client)
    doc_id = _create_doc(models)

    storage = importlib.import_module("storage")
    storage.storage_client.put = MagicMock()

    data = {"file": (io.BytesIO(b"data"), "test.txt")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    assert doc.minor_version == 0
    revs = session.query(models.DocumentRevision).filter_by(doc_id=doc_id).all()
    assert len(revs) == 0
    session.close()
    storage.storage_client.put.assert_not_called()


def test_upload_new_version_too_large(client, app_models, monkeypatch):
    app_module, models = app_models
    _login(client)
    doc_id = _create_doc(models)

    storage = importlib.import_module("storage")
    storage.storage_client.put = MagicMock()

    app_module.MAX_UPLOAD_SIZE = 100

    class CountingIO(io.BytesIO):
        def __init__(self, *args, **kwargs):
            self.reads = 0
            super().__init__(*args, **kwargs)
        def read(self, *args, **kwargs):
            self.reads += 1
            return super().read(*args, **kwargs)

    file_obj = CountingIO(b"x" * 101)
    data = {"file": (file_obj, "test.pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert file_obj.reads == 2

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    assert doc.minor_version == 0
    revs = session.query(models.DocumentRevision).filter_by(doc_id=doc_id).all()
    assert len(revs) == 0
    session.close()
    storage.storage_client.put.assert_not_called()


def test_upload_new_version_forbidden(client, app_models):
    app_module, models = app_models
    _login(client)
    doc_id = _create_doc(models, can_upload=False)

    data = {"file": (io.BytesIO(b"data"), "test.pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 403
