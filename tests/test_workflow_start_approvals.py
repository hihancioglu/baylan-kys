import os
import uuid
import pytest
import importlib
from pathlib import Path
import sys
from datetime import datetime

os.environ.setdefault("S3_ENDPOINT", "http://s3")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models():
    app_module = importlib.import_module("app")
    models_module = importlib.import_module("models")
    app_module.notify_revision_time = lambda *args, **kwargs: None
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    app_module.app.add_url_rule("/", "index", lambda: "index")
    return app_module.app, models_module


@pytest.fixture()
def client(app_models):
    app, _ = app_models
    return app.test_client()


@pytest.fixture()
def workflow_data(app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    contributor = m.User(username=f"contrib_{uid}")
    reviewer = m.User(username=f"reviewer_{uid}")
    approver = m.User(username=f"approver_{uid}")
    doc = m.Document(doc_key=f"sample_{uid}.docx", title="Sample Doc")
    session.add_all([contributor, reviewer, approver, doc])
    session.commit()
    ids = {
        "doc_id": doc.id,
        "reviewer_id": reviewer.id,
        "approver_id": approver.id,
        "contrib_id": contributor.id,
    }
    session.close()
    return app, m, ids


def test_workflow_start_creates_steps_and_approvals(client, workflow_data):
    app, m, ids = workflow_data
    doc_id = ids["doc_id"]
    reviewer_id = ids["reviewer_id"]
    approver_id = ids["approver_id"]
    contrib_id = ids["contrib_id"]

    with client.session_transaction() as sess:
        sess["user"] = {"id": contrib_id}
        sess["roles"] = ["contributor"]

    resp = client.post(
        "/api/workflow/start",
        json={
            "doc_id": doc_id,
            "reviewers": [
                {
                    "user_id": reviewer_id,
                    "required_role": "reviewer",
                    "due_at": "2030-01-01T00:00:00",
                }
            ],
            "approvers": [
                {
                    "user_id": approver_id,
                    "required_role": "approver",
                    "due_at": "2030-01-02T00:00:00",
                }
            ],
        },
    )
    assert resp.status_code == 200

    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.status == "Review"
    wf = doc.workflow
    assert wf is not None
    assert wf.current_step == 1
    assert wf.state == "review"
    steps = (
        session.query(m.WorkflowStep)
        .filter_by(doc_id=doc_id)
        .order_by(m.WorkflowStep.step_order)
        .all()
    )
    assert [s.user_id for s in steps] == [reviewer_id, approver_id]
    assert [s.step_order for s in steps] == [1, 2]
    assert [s.step_type for s in steps] == ["review", "approval"]
    assert [s.required_role for s in steps] == ["reviewer", "approver"]
    assert [s.due_at for s in steps] == [
        datetime.fromisoformat("2030-01-01T00:00:00"),
        datetime.fromisoformat("2030-01-02T00:00:00"),
    ]
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": reviewer_id}
        sess["roles"] = ["reader"]
    resp = client.get(f"/documents/{doc_id}/workflow")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "reviewer" in html
    assert "2030-01-01" in html

    with client.session_transaction() as sess:
        sess["user"] = {"id": reviewer_id}
        sess["roles"] = ["reviewer"]
    resp = client.get("/approvals", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Sample Doc" in html
    assert "Review" in html
    assert "reviewer" in html
    assert "2030-01-01" in html

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = ["approver"]
    resp = client.get("/approvals", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Sample Doc" in html
    assert "Approval" in html
    assert "approver" in html
    assert "2030-01-02" in html
