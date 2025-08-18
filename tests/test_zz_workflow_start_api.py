import os
import uuid
import pytest
import importlib
from pathlib import Path
import sys

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


def _get_app_models():
    a = importlib.import_module("app")
    m = importlib.import_module("models")
    return a, m


def _prepare_data(suffix: str = ""):
    a, m = _get_app_models()
    app = a.app
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    contributor = m.User(username=f"contrib_{suffix}_{uid}")
    reviewer = m.User(username=f"reviewer_{suffix}_{uid}")
    approver = m.User(username=f"approver_{suffix}_{uid}")
    doc_key = f"sample_{suffix}_{uid}.docx"
    doc = m.Document(doc_key=doc_key, title=f"Sample Doc{suffix}")
    session.add_all([contributor, reviewer, approver, doc])
    session.commit()
    ids = (doc.id, reviewer.id, approver.id, contributor.id)
    session.close()
    a.notify_revision_time = lambda *args, **kwargs: None
    app.config["WTF_CSRF_ENABLED"] = False
    return app, m, ids


@pytest.fixture()
def client():
    a, _ = _get_app_models()
    return a.app.test_client()


def test_workflow_start_status_and_steps(client):
    app, m, ids = _prepare_data("a")
    doc_id, reviewer_id, approver_id, contrib_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": contrib_id}
        sess["roles"] = ["contributor"]
    resp = client.post(
        "/api/workflow/start",
        json={
            "doc_id": doc_id,
            "reviewers": [reviewer_id],
            "approvers": [approver_id],
        },
    )
    assert resp.status_code == 200
    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.status == "Review"
    steps = (
        session.query(m.WorkflowStep)
        .filter_by(doc_id=doc_id)
        .order_by(m.WorkflowStep.step_order)
        .all()
    )
    assert [s.user_id for s in steps] == [reviewer_id, approver_id]
    assert [s.step_order for s in steps] == [1, 2]
    assert [s.step_type for s in steps] == ["review", "approval"]
    session.close()


def test_workflow_start_queue_visibility(client):
    app, m, ids = _prepare_data("b")
    doc_id, reviewer_id, approver_id, contrib_id = ids
    with client.session_transaction() as sess:
        sess["user"] = {"id": contrib_id}
        sess["roles"] = ["contributor"]
    client.post(
        "/api/workflow/start",
        json={
            "doc_id": doc_id,
            "reviewers": [reviewer_id],
            "approvers": [approver_id],
        },
    )

    with client.session_transaction() as sess:
        sess["user"] = {"id": reviewer_id}
        sess["roles"] = []
    resp = client.get(
        "/api/dashboard/cards/pending", headers={"HX-Request": "true"}
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert f"Sample Docb" in html

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = []
    resp = client.get(
        "/api/dashboard/cards/pending", headers={"HX-Request": "true"}
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert f"Sample Docb" in html


def test_workflow_start_notifies_all_assignees(client):
    app, m, ids = _prepare_data("c")
    doc_id, reviewer_id, approver_id, contrib_id = ids
    calls = []

    import app as app_module

    def fake_notify_revision_time(doc, user_ids):
        calls.append(list(user_ids))

    app_module.notify_revision_time = fake_notify_revision_time

    with client.session_transaction() as sess:
        sess["user"] = {"id": contrib_id}
        sess["roles"] = ["contributor"]
    resp = client.post(
        "/api/workflow/start",
        json={
            "doc_id": doc_id,
            "reviewers": [reviewer_id],
            "approvers": [approver_id],
        },
    )
    assert resp.status_code == 200
    assert len(calls) == 1
    assert set(calls[0]) == {reviewer_id, approver_id}
