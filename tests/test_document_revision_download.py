import sys
import sys
import importlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

os = __import__("os")

os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET_MAIN", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_modules():
    app_module = importlib.import_module("app")
    models_module = importlib.import_module("portal.models")
    sys.modules["models"] = models_module
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module, models_module


def _setup_revision(models, can_download: bool):
    session = models.SessionLocal()
    try:
        role = models.Role(id=1, name="reader")
        user = models.User(id=1, username="u1")
        user.roles.append(role)
        doc = models.Document(id=1, file_key="foo/bar.txt", title="t")
        rev = models.DocumentRevision(
            id=1,
            doc_id=doc.id,
            major_version=1,
            minor_version=0,
            file_key="foo/rev1.txt",
        )
        session.add_all([role, user, doc, rev])
        session.commit()
        perm = models.DocumentPermission(
            role_id=role.id, doc_id=doc.id, can_download=can_download
        )
        session.add(perm)
        session.commit()
    finally:
        session.close()


def test_revision_download_redirects_and_logs(app_modules):
    app_module, models = app_modules
    _setup_revision(models, can_download=True)
    app_module.storage_client.generate_presigned_url = MagicMock(
        return_value="/signed"
    )
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["reader"]
    resp = client.get("/documents/1/revisions/1/download")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/signed"
    app_module.storage_client.generate_presigned_url.assert_called_once_with(
        "foo/rev1.txt"
    )
    log_session = models.SessionLocal()
    try:
        logs = (
            log_session.query(models.AuditLog)
            .filter_by(doc_id=1, action="download_revision")
            .all()
        )
        assert len(logs) == 1
    finally:
        log_session.close()


def test_revision_download_forbidden(app_modules):
    app_module, models = app_modules
    _setup_revision(models, can_download=False)
    app_module.storage_client.generate_presigned_url = MagicMock(
        return_value="/signed"
    )
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["reader"]
    resp = client.get("/documents/1/revisions/1/download")
    assert resp.status_code == 403
    app_module.storage_client.generate_presigned_url.assert_not_called()


def test_revision_download_missing_revision(app_modules):
    app_module, models = app_modules
    _setup_revision(models, can_download=True)
    app_module.storage_client.generate_presigned_url = MagicMock(
        return_value="/signed"
    )
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["reader"]
    resp = client.get("/documents/1/revisions/999/download")
    assert resp.status_code == 404
    app_module.storage_client.generate_presigned_url.assert_not_called()
