import io
import importlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock
from datetime import datetime, timedelta

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
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    app_module.notify_user = lambda *a, **k: None
    return app_module, models_module


@pytest.fixture()
def client(app_models):
    app_module, _ = app_models
    return app_module.app.test_client()


def _login(client, user_id, roles=None):
    with client.session_transaction() as sess:
        sess["user"] = {"id": user_id, "name": f"User{user_id}"}
        sess["roles"] = roles or ["contributor"]


def _create_doc_and_users(models):
    session = models.SessionLocal()
    u1 = models.User(username="u1")
    u2 = models.User(username="u2")
    session.add_all([u1, u2])
    session.commit()
    doc = models.Document(
        file_key="orig.pdf",
        title="Doc",
        status="Published",
        mime="application/pdf",
    )
    session.add(doc)
    session.commit()
    doc_id = doc.id
    u1_id, u2_id = u1.id, u2.id
    session.close()
    return doc_id, u1_id, u2_id


def test_concurrent_upload_blocked_and_expiry(client, app_models):
    app_module, models = app_models
    storage = importlib.import_module("storage")
    storage.storage_client.put = MagicMock()
    doc_id, user1, user2 = _create_doc_and_users(models)

    _login(client, user1)
    resp = client.post(f"/api/documents/{doc_id}/checkout")
    assert resp.status_code == 200

    _login(client, user2)
    data = {"file": (io.BytesIO(b"data"), "test.pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 409

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.lock_expires_at = datetime.utcnow() - timedelta(minutes=1)
    session.commit()
    session.close()

    services = importlib.import_module("services")
    services.clear_expired_locks()

    _login(client, user2)
    data = {"file": (io.BytesIO(b"data2"), "test.pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
