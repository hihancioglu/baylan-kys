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


def _setup_document(models):
    session = models.SessionLocal()
    try:
        role = models.Role(id=1, name="reader")
        user = models.User(id=1, username="u1")
        user.roles.append(role)
        doc = models.Document(id=1, file_key="foo/bar.txt", title="t")
        session.add_all([role, user, doc])
        session.commit()
        perm = models.DocumentPermission(role_id=role.id, doc_id=doc.id, can_download=True)
        session.add(perm)
        session.commit()
    finally:
        session.close()


def test_file_access_requires_role(app_modules):
    app_module, models = app_modules
    _setup_document(models)
    client = app_module.app.test_client()

    # Without required role expect 403
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = []
    resp = client.get("/files/foo/bar.txt")
    assert resp.status_code == 403

    # With correct role expect 200 with signed URL
    app_module.storage_client.generate_presigned_url = MagicMock(return_value="/signed")
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["reader"]

    resp = client.get("/files/foo/bar.txt", follow_redirects=True)
    assert resp.status_code == 200
    assert resp.request.path == "/signed"
    assert "signed-url" in resp.get_data(as_text=True)
