import os
import importlib
from pathlib import Path
import sys
import uuid

import pytest
from unittest.mock import MagicMock

# Ensure environment variables before importing application
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ["S3_BUCKET_MAIN"] = "local"

# Make application modules importable
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
    return app_module.app, models_module


@pytest.fixture()
def client(app_models):
    app, _ = app_models
    return app.test_client()


def test_start_revision_increments_version_and_logs(app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    doc = m.Document(doc_key=f"doc_{uid}.docx", title="Doc", status="Published", revision_notes="orig")
    session.add(doc)
    session.commit()
    from app import _start_revision

    user = {"id": 1}
    doc_id = doc.id
    _start_revision(doc, "minor", "new notes", user, session)
    session.close()

    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.major_version == 1
    assert doc.minor_version == 1
    assert doc.status == "Draft"

    revisions = session.query(m.DocumentRevision).filter_by(doc_id=doc_id).all()
    assert len(revisions) == 1
    assert revisions[0].major_version == 1 and revisions[0].minor_version == 0
    session.close()

    log_session = m.SessionLocal()
    logs = log_session.query(m.AuditLog).filter_by(doc_id=doc_id, action="start_revision").all()
    log_session.close()
    assert len(logs) == 1


def test_rollback_document_creates_new_revision_and_serves_content(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    role = m.Role(id=1, name="reader")
    user_db = m.User(id=1, username="u1")
    user_db.roles.append(role)
    doc = m.Document(
        file_key="placeholder",
        title="Doc",
        status="Published",
        major_version=1,
        minor_version=1,
        revision_notes="curr",
        mime="application/pdf",
    )
    session.add_all([role, user_db, doc])
    session.commit()
    doc.file_key = f"documents/{doc.id}/versions/1.1.txt"
    rev = m.DocumentRevision(
        doc_id=doc.id,
        major_version=1,
        minor_version=0,
        file_key=f"documents/{doc.id}/versions/1.0.txt",
        revision_notes="orig",
    )
    perm = m.DocumentPermission(role_id=role.id, doc_id=doc.id, can_download=True)
    session.add_all([rev, perm])
    session.commit()
    doc_id = doc.id
    session.close()

    storage = importlib.import_module("storage")
    storage.storage_client.copy = MagicMock()
    storage.storage_client.generate_presigned_url = MagicMock(return_value="/signed")

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["reviewer", "reader"]

    resp = client.post(f"/api/documents/{doc_id}/rollback", json={"version": "v1.0"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["minor_version"] == 2

    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    dest_key = doc.doc_key
    assert doc.minor_version == 2
    assert dest_key.endswith("1.2.txt")
    revisions = session.query(m.DocumentRevision).filter_by(doc_id=doc_id).all()
    minors = {r.minor_version for r in revisions}
    assert minors == {0, 1}
    session.close()

    storage.storage_client.copy.assert_called_once_with(
        CopySource={"Key": f"documents/{doc_id}/versions/1.0.txt"},
        Key=f"documents/{doc_id}/versions/1.2.txt",
    )

    resp = client.get(f"/files/{dest_key}")
    assert resp.status_code == 302
    storage.storage_client.generate_presigned_url.assert_called_with(dest_key, expires_in=None)


def test_compare_nonexistent_document_returns_404(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    last = session.query(m.Document).order_by(m.Document.id.desc()).first()
    session.close()
    missing_id = (last.id if last else 0) + 1

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["reader"]

    resp = client.get(f"/documents/{missing_id}/compare?rev_id=1&rev_id=2")
    assert resp.status_code == 404
