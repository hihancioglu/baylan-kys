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
    return app_module.app, models_module


@pytest.fixture()
def client(app_models):
    app, _ = app_models
    return app.test_client()


@pytest.fixture()
def setup_data(app_models):
    app, m = app_models
    session = m.SessionLocal()
    approver = m.User(username="approver")
    doc1 = m.Document(doc_key="doc1.docx", title="Doc1", status="Review")
    doc2 = m.Document(doc_key="doc2.docx", title="Doc2", status="Review")
    session.add_all([approver, doc1, doc2])
    session.commit()
    step1 = m.WorkflowStep(doc_id=doc1.id, step_order=1, user_id=approver.id, status="Pending", step_type="approval")
    step2 = m.WorkflowStep(doc_id=doc2.id, step_order=1, user_id=approver.id, status="Pending", step_type="approval")
    session.add_all([step1, step2])
    session.commit()
    ids = (approver.id, step1.id, step2.id)
    session.close()
    return m, ids


def test_api_approve_step(client, setup_data):
    m, ids = setup_data
    approver_id, step_id, _ = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = ["approver"]
    with patch("app.broadcast_counts") as broadcast_mock:
        resp = client.post(
            f"/api/approvals/{step_id}/approve",
            json={"comment": "looks good"},
        )
        broadcast_mock.assert_called_once()
    assert resp.status_code == 200
    assert "Approved" in resp.headers.get("HX-Trigger", "")
    html = resp.get_data(as_text=True)
    assert f'id="step-{step_id}"' in html
    assert "looks good" in html
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.status == "Approved"
    assert step.comment == "looks good"
    assert step.approved_at is not None
    session.close()


def test_api_reject_step(client, setup_data):
    m, ids = setup_data
    approver_id, _, step_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = ["approver"]
    resp = client.post(
        f"/api/approvals/{step_id}/reject",
        json={"comment": "needs work"},
    )
    assert resp.status_code == 200
    assert "Rejected" in resp.headers.get("HX-Trigger", "")
    html = resp.get_data(as_text=True)
    assert "needs work" in html
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.status == "Rejected"
    assert step.comment == "needs work"
    assert step.approved_at is not None
    session.close()
