import os
from pathlib import Path
import sys
from datetime import datetime
import importlib

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

# Make application modules importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))

import pytest


def get_models():
    import models as m
    importlib.reload(m)
    return m


def get_app_module():
    import app as a
    importlib.reload(a)
    return a


@pytest.fixture(autouse=True)
def models():
    _db_path = Path("test_dashboard_api.db")
    if _db_path.exists():
        _db_path.unlink()
    os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
    m = get_models()
    Base = m.Base
    engine = m.engine
    SessionLocal = m.SessionLocal
    Document = m.Document
    WorkflowStep = m.WorkflowStep
    DocumentRevision = m.DocumentRevision
    Acknowledgement = m.Acknowledgement
    User = m.User

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()

    user = User(username="tester", email="tester@example.com")
    session.add(user)
    session.commit()

    assigned_doc1 = Document(doc_key="assigned1.docx", title="Assigned Doc 1", status="Review")
    assigned_doc2 = Document(doc_key="assigned2.docx", title="Assigned Doc 2", status="Review")
    unassigned_doc = Document(doc_key="unassigned.docx", title="Unassigned Doc", status="Review")
    mandatory_doc1 = Document(doc_key="mandatory1.docx", title="Mandatory Doc 1", status="Published")
    mandatory_doc2 = Document(doc_key="mandatory2.docx", title="Mandatory Doc 2", status="Published")
    session.add_all([assigned_doc1, assigned_doc2, unassigned_doc, mandatory_doc1, mandatory_doc2])
    session.commit()

    step1 = WorkflowStep(doc_id=assigned_doc1.id, step_order=1, approver="approver", status="Pending")
    step2 = WorkflowStep(doc_id=assigned_doc2.id, step_order=1, approver="approver", status="Pending")
    step3 = WorkflowStep(doc_id=unassigned_doc.id, step_order=1, approver=None, status="Pending")
    session.add_all([step1, step2, step3])
    session.commit()

    ack1 = Acknowledgement(user_id=user.id, doc_id=mandatory_doc1.id)
    ack2 = Acknowledgement(user_id=user.id, doc_id=mandatory_doc2.id)
    session.add_all([ack1, ack2])
    session.commit()

    rev1 = DocumentRevision(doc_id=mandatory_doc1.id, major_version=1, minor_version=0)
    rev2 = DocumentRevision(doc_id=mandatory_doc2.id, major_version=1, minor_version=0)
    session.add_all([rev1, rev2])
    session.commit()

    session.close()
    return m


@pytest.fixture()
def app_module(models):
    return get_app_module()


@pytest.fixture()
def client(app_module):
    return app_module.app.test_client()


def test_api_pending_approvals(client, models):
    SessionLocal = models.SessionLocal
    WorkflowStep = models.WorkflowStep

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["approver"]
    resp = client.get("/api/dashboard/pending-approvals")
    assert resp.status_code == 200
    data = resp.get_json()
    assert set(data.keys()) == {"items", "error"}
    assert data["error"] is None
    assert len(data["items"]) == 2

    resp = client.get("/api/dashboard/pending-approvals?limit=1")
    assert resp.status_code == 200
    assert len(resp.get_json()["items"]) == 1

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/pending-approvals")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["items"]) == 1
    assert data["items"][0][0] == "Unassigned Doc"

    db = SessionLocal()
    db.query(WorkflowStep).delete()
    db.commit()
    db.close()
    resp = client.get("/api/dashboard/pending-approvals")
    assert resp.status_code == 200
    assert resp.get_json()["items"] == []


def test_api_mandatory_reading(client, models):
    SessionLocal = models.SessionLocal
    Acknowledgement = models.Acknowledgement

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/mandatory-reading")
    assert resp.status_code == 200
    data = resp.get_json()
    assert set(data.keys()) == {"items", "error"}
    assert data["error"] is None
    assert len(data["items"]) == 2

    resp = client.get("/api/dashboard/mandatory-reading?limit=1")
    assert resp.status_code == 200
    assert len(resp.get_json()["items"]) == 1

    db = SessionLocal()
    db.query(Acknowledgement).update({Acknowledgement.acknowledged_at: datetime.utcnow()})
    db.commit()
    db.close()
    resp = client.get("/api/dashboard/mandatory-reading")
    assert resp.status_code == 200
    assert resp.get_json()["items"] == []


def test_api_recent_changes(client, models):
    SessionLocal = models.SessionLocal
    DocumentRevision = models.DocumentRevision

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/recent-changes")
    assert resp.status_code == 200
    data = resp.get_json()
    assert set(data.keys()) == {"items", "error"}
    assert data["error"] is None
    assert len(data["items"]) == 2

    resp = client.get("/api/dashboard/recent-changes?limit=1")
    assert resp.status_code == 200
    assert len(resp.get_json()["items"]) == 1

    db = SessionLocal()
    db.query(DocumentRevision).delete()
    db.commit()
    db.close()
    resp = client.get("/api/dashboard/recent-changes")
    assert resp.status_code == 200
    assert resp.get_json()["items"] == []


def test_api_search_shortcuts(client, app_module, monkeypatch):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/search-shortcuts")
    assert resp.status_code == 200
    data = resp.get_json()
    assert set(data.keys()) == {"items", "error"}
    assert data["error"] is None
    assert len(data["items"]) == 3

    resp = client.get("/api/dashboard/search-shortcuts?limit=1")
    assert resp.status_code == 200
    assert len(resp.get_json()["items"]) == 1

    monkeypatch.setattr(app_module, "_get_search_shortcuts", lambda limit=5: [])
    resp = client.get("/api/dashboard/search-shortcuts")
    assert resp.status_code == 200
    assert resp.get_json()["items"] == []
