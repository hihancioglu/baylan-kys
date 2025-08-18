import os
import importlib
from pathlib import Path
import sys
import uuid

import pytest

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
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


def test_compare_config_returns_expected_fields(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    doc_key = f"doc_{uid}.docx"
    doc = m.Document(doc_key=doc_key, title="Doc", status="Published", major_version=2, minor_version=0)
    session.add(doc)
    session.commit()
    rev = m.DocumentRevision(
        doc_id=doc.id,
        major_version=1,
        minor_version=0,
        track_changes={"url": "http://s3/old.docx"},
    )
    session.add(rev)
    session.commit()
    doc_id = doc.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["reader"]

    resp = client.get(f"/api/documents/compare?doc_id={doc_id}&from=1.0&to=2.0")
    assert resp.status_code == 200
    data = resp.get_json()
    config = data["config"]
    assert config["document"]["key"] == f"{doc_key}:1.0"
    assert config["document"]["url"] == "http://s3/old.docx"
    assert config["editorConfig"]["compareFile"]["key"] == f"{doc_key}:2.0"
    assert config["editorConfig"]["compareFile"]["url"] == f"http://s3/local/{doc_key}"
    assert data["token"]
    assert data["token_header"] == "AuthorizationJwt"


def test_revert_document_preserves_history(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    doc = m.Document(doc_key=f"doc_{uid}.docx", title="Doc", status="Published", revision_notes="orig")
    session.add(doc)
    session.commit()
    from app import _start_revision

    user = {"id": 1}
    doc_id = doc.id
    _start_revision(doc, "minor", "rev1", user, session)
    rev_id = (
        session.query(m.DocumentRevision)
        .filter_by(doc_id=doc_id, major_version=1, minor_version=0)
        .one()
        .id
    )
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["reviewer"]

    resp = client.post(f"/documents/{doc_id}/revert/{rev_id}")
    assert resp.status_code == 302

    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.major_version == 1
    assert doc.minor_version == 2

    revisions = session.query(m.DocumentRevision).filter_by(doc_id=doc_id).all()
    minor_versions = {r.minor_version for r in revisions}
    assert 0 in minor_versions and 2 in minor_versions
    session.close()


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
