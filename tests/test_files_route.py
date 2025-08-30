import os
import sys
import importlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET_MAIN", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_modules():
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    @app_module.app.route("/signed")
    def signed():
        return "signed-url"

    return app_module, models_module


@pytest.fixture()
def client(app_modules):
    app_module, _ = app_modules
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["reader"]
    return client


def _setup_document(models, allow_download=True):
    session = models.SessionLocal()
    try:
        role = models.Role(id=1, name="reader")
        user = models.User(id=1, username="u1")
        user.roles.append(role)
        doc = models.Document(id=1, file_key="foo/bar.txt", title="t")
        session.add_all([role, user, doc])
        session.commit()
        if allow_download:
            perm = models.DocumentPermission(role_id=role.id, doc_id=doc.id, can_download=True)
            session.add(perm)
            session.commit()
    finally:
        session.close()


def test_files_route_redirects_when_authorized(app_modules, client):
    app_module, models = app_modules
    _setup_document(models, allow_download=True)
    app_module.storage_client.generate_presigned_url = MagicMock(return_value="/signed")
    resp = client.get("/files/foo/bar.txt", follow_redirects=True)
    assert resp.status_code == 200
    assert resp.request.path == "/signed"
    assert "signed-url" in resp.get_data(as_text=True)


def test_files_route_returns_403_without_permission(app_modules, client):
    app_module, models = app_modules
    _setup_document(models, allow_download=False)
    app_module.storage_client.generate_presigned_url = MagicMock(return_value="/signed")
    resp = client.get("/files/foo/bar.txt")
    assert resp.status_code == 403


def test_files_route_sets_cache_control_header(app_modules, client):
    app_module, models = app_modules
    _setup_document(models, allow_download=True)
    app_module.storage_client.generate_presigned_url = MagicMock(return_value="/signed")
    resp = client.get("/files/foo/bar.txt")
    assert resp.status_code == 302
    assert resp.headers["Cache-Control"] == "public, max-age=86400"


def test_files_route_respects_size_limit(app_modules, client):
    app_module, models = app_modules
    _setup_document(models, allow_download=True)
    backend = app_module.storage_client
    # Ensure the real method is used (it may be monkeypatched by previous tests)
    backend.generate_presigned_url = type(backend).generate_presigned_url.__get__(
        backend, type(backend)
    )
    backend.client.head_object = MagicMock(return_value={"ContentLength": 51 * 1024 * 1024})
    backend.client.generate_presigned_url = MagicMock(return_value="/signed")
    resp = client.get("/files/foo/bar.txt")
    assert resp.status_code == 404
    backend.client.generate_presigned_url.assert_not_called()
