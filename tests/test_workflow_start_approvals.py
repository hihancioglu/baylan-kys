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
    m.Base.metadata.create_all(bind=m.engine)
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
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": reviewer_id}
        sess["roles"] = ["reviewer"]
    resp = client.get("/approvals", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Sample Doc" in html
