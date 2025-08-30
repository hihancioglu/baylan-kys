import os
import sys
import uuid
import importlib
from pathlib import Path

import pytest

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


def test_current_step_updates_on_approval(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    user = m.User(username=f"user_{uid}")
    doc = m.Document(doc_key=f"doc_{uid}.docx", title="Doc", status="Review")
    session.add_all([user, doc])
    session.commit()
    user_id = user.id
    wf = m.DocWorkflow(document_id=doc.id, state="review", current_step=1)
    doc.workflow = wf
    session.add(wf)
    step1 = m.WorkflowStep(doc_id=doc.id, step_order=1, user_id=user_id, step_type="review")
    step2 = m.WorkflowStep(doc_id=doc.id, step_order=2, step_type="approval")
    session.add_all([step1, step2])
    session.commit()
    step_id = step1.id
    wf_id = wf.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": user_id}
        sess["roles"] = ["reviewer"]
    resp = client.post(f"/api/approvals/{step_id}/approve", json={})
    assert resp.status_code == 200

    session = m.SessionLocal()
    wf = session.get(m.DocWorkflow, wf_id)
    assert wf.current_step == 2
    session.close()
