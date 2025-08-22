import os
from pathlib import Path
import sys
from datetime import datetime
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
    return m


def get_app_module():
    import app as a
    return a


@pytest.fixture(autouse=True)
def models(reset_database):
    m = get_models()
    SessionLocal = m.SessionLocal
    Document = m.Document
    DocumentStandard = m.DocumentStandard
    WorkflowStep = m.WorkflowStep
    DocumentRevision = m.DocumentRevision
    Acknowledgement = m.Acknowledgement
    User = m.User

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

    sd1 = DocumentStandard(doc_id=assigned_doc1.id, standard_code="STD1")
    sd2 = DocumentStandard(doc_id=mandatory_doc1.id, standard_code="STD1")
    sd3 = DocumentStandard(doc_id=mandatory_doc2.id, standard_code="STD2")
    session.add_all([sd1, sd2, sd3])
    session.commit()

    step1 = WorkflowStep(doc_id=assigned_doc1.id, step_order=1, user_id=user.id, status="Pending", step_type="approval")
    step2 = WorkflowStep(doc_id=assigned_doc2.id, step_order=1, user_id=user.id, status="Pending", step_type="approval")
    step3 = WorkflowStep(doc_id=unassigned_doc.id, step_order=1, user_id=None, status="Pending", step_type="approval")
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
        sess["roles"] = []
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
        sess["user"] = {"id": 2, "name": "Other"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/pending-approvals")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["items"]) == 0

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


def test_api_standard_summary(client, models):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/standard-summary")
    assert resp.status_code == 200
    data = resp.get_json()
    assert any(d["standard"] == "STD1" and d["count"] == 2 for d in data)
    assert any(d["standard"] == "STD2" and d["count"] == 1 for d in data)


def test_document_standard_relationship(models):
    SessionLocal = models.SessionLocal
    Document = models.Document
    session_db = SessionLocal()
    doc = session_db.query(Document).filter_by(doc_key="assigned1.docx").one()
    assert [s.standard_code for s in doc.standards] == ["STD1"]
    session_db.close()


def test_reports_standard_summary(client, models, app_module):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = [app_module.RoleEnum.AUDITOR.value]

    resp = client.get("/reports/standard-summary?format=json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert any(d["standard"] == "STD1" and d["count"] == 2 for d in data)
    assert any(d["standard"] == "STD2" and d["count"] == 1 for d in data)

    resp = client.get("/reports/standard-summary?format=csv")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    text = resp.data.decode()
    assert "standard,count" in text
    assert "STD1" in text and "STD2" in text

    resp = client.get("/reports/export?kind=standard-summary&type=pdf")
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data.startswith(b"%PDF")
