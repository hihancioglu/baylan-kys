import os
import importlib
from pathlib import Path
import sys
import pytest
from unittest.mock import patch

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models():
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    models_module.Base.metadata.create_all(bind=models_module.engine)
    return app_module.app, models_module


@pytest.fixture()
def client(app_models):
    app, _ = app_models
    return app.test_client()


def test_document_status_updates_when_all_steps_approved(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    approver = m.User(username="approver")
    doc = m.Document(doc_key="doc.docx", title="Doc", status="Review")
    session.add_all([approver, doc])
    session.commit()
    step1 = m.WorkflowStep(doc_id=doc.id, step_order=1, user_id=approver.id, status="Pending", step_type="approval")
    step2 = m.WorkflowStep(doc_id=doc.id, step_order=2, user_id=approver.id, status="Pending", step_type="approval")
    session.add_all([step1, step2])
    session.commit()
    doc_id = doc.id
    step1_id = step1.id
    step2_id = step2.id
    approver_id = approver.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = ["approver"]
    with patch("app.notify_approval_queue"):
        resp = client.post(f"/api/approvals/{step1_id}/approve", json={})
    assert resp.status_code == 200
    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.status == "Review"
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = ["approver"]
    resp = client.post(f"/api/approvals/{step2_id}/approve", json={})
    assert resp.status_code == 200
    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.status == "Approved"
    session.close()
