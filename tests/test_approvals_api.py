import os
import importlib
from pathlib import Path
import sys
import pytest
from unittest.mock import patch

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


@pytest.fixture()
def setup_data(app_models):
    app, m = app_models
    session = m.SessionLocal()
    approver = m.User(username="approver")
    new_user = m.User(username="new")
    doc1 = m.Document(doc_key="doc1.docx", title="Doc1", status="Review")
    doc2 = m.Document(doc_key="doc2.docx", title="Doc2", status="Review")
    session.add_all([approver, new_user, doc1, doc2])
    session.commit()
    step1 = m.WorkflowStep(doc_id=doc1.id, step_order=1, user_id=approver.id, status="Pending", step_type="approval")
    step2 = m.WorkflowStep(doc_id=doc2.id, step_order=1, user_id=approver.id, status="Pending", step_type="approval")
    session.add_all([step1, step2])
    session.commit()
    ids = (approver.id, step1.id, step2.id, new_user.id)
    session.close()
    return m, ids


def test_api_approve_step(client, setup_data):
    m, ids = setup_data
    approver_id, step_id, _, _ = ids
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
    logs = session.query(m.AuditLog).filter_by(entity_type="WorkflowStep", entity_id=step_id, action="approved").all()
    assert len(logs) == 1
    assert logs[0].payload["comment"] == "looks good"
    session.close()


def test_api_reject_step(client, setup_data):
    m, ids = setup_data
    approver_id, _, step_id, _ = ids
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
    logs = session.query(m.AuditLog).filter_by(entity_type="WorkflowStep", entity_id=step_id, action="rejected").all()
    assert len(logs) == 1
    assert logs[0].payload["comment"] == "needs work"
    session.close()


def test_api_undo_step(client, setup_data):
    m, ids = setup_data
    approver_id, step_id, _, _ = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = ["approver"]
    # Approve first to change state
    client.post(f"/api/approvals/{step_id}/approve", json={"comment": "ok"})
    with patch("app.broadcast_counts") as broadcast_mock:
        resp = client.post(f"/api/approvals/{step_id}/undo")
        broadcast_mock.assert_called_once()
    assert resp.status_code == 200
    assert "Reverted" in resp.headers.get("HX-Trigger", "")
    html = resp.get_data(as_text=True)
    assert f'hx-post="/api/approvals/{step_id}/approve"' in html
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.status == "Pending"
    assert step.comment is None
    assert step.approved_at is None
    doc = session.get(m.Document, step.doc_id)
    assert doc.status == "Review"
    logs = session.query(m.AuditLog).filter_by(entity_type="WorkflowStep", entity_id=step_id, action="pending").all()
    assert len(logs) == 1
    session.close()


def test_api_approve_step_forbidden_for_other_user(client, setup_data):
    m, ids = setup_data
    _, step_id, _, new_user_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": new_user_id}
        sess["roles"] = ["approver"]
    resp = client.post(f"/api/approvals/{step_id}/approve", json={})
    assert resp.status_code == 403
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.status == "Pending"
    logs = session.query(m.AuditLog).filter_by(action="approve_forbidden").all()
    assert len(logs) == 1
    session.close()


def test_api_reject_step_forbidden_for_other_user(client, setup_data):
    m, ids = setup_data
    _, step_id, _, new_user_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": new_user_id}
        sess["roles"] = ["approver"]
    resp = client.post(f"/api/approvals/{step_id}/reject", json={})
    assert resp.status_code == 403
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.status == "Pending"
    logs = session.query(m.AuditLog).filter_by(action="reject_forbidden").all()
    assert len(logs) == 1
    session.close()


def test_api_reassign_step(client, setup_data):
    m, ids = setup_data
    approver_id, step_id, _, new_user_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = ["approver"]
    with patch("app.notify_approval_queue") as notify_mock, patch(
        "app.broadcast_counts"
    ) as broadcast_mock:
        resp = client.post(
            f"/api/approvals/{step_id}/reassign",
            json={"user_id": new_user_id},
        )
        assert resp.status_code == 200
        broadcast_mock.assert_called_once()
        notify_mock.assert_called_once()
        assert notify_mock.call_args[0][1] == [new_user_id]
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.user_id == new_user_id
    assert step.required_role is None
    logs = session.query(m.AuditLog).filter_by(entity_type="WorkflowStep", entity_id=step_id, action="reassigned").all()
    assert len(logs) == 1
    assert logs[0].payload["user_id"] == new_user_id
    session.close()



def test_api_reassign_step_requires_role(client, setup_data):
    m, ids = setup_data
    approver_id, step_id, _, new_user_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = []
    resp = client.post(
        f"/api/approvals/{step_id}/reassign",
        json={"user_id": new_user_id},
    )
    assert resp.status_code == 403


def test_approve_step_forbidden_for_other_user(client, setup_data):
    m, ids = setup_data
    _, step_id, _, new_user_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": new_user_id}
        sess["roles"] = ["approver"]
    resp = client.post(f"/approvals/{step_id}/approve", data={"comment": ""})
    assert resp.status_code == 403
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.status == "Pending"
    logs = session.query(m.AuditLog).filter_by(action="approve_forbidden").all()
    assert len(logs) == 1
    session.close()


def test_reject_step_forbidden_for_other_user(client, setup_data):
    m, ids = setup_data
    _, step_id, _, new_user_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": new_user_id}
        sess["roles"] = ["approver"]
    resp = client.post(f"/approvals/{step_id}/reject", data={"comment": ""})
    assert resp.status_code == 403
    session = m.SessionLocal()
    step = session.get(m.WorkflowStep, step_id)
    assert step.status == "Pending"
    logs = session.query(m.AuditLog).filter_by(action="reject_forbidden").all()
    assert len(logs) == 1
    session.close()
