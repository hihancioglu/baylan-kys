import os
import sys
import uuid
import importlib
from pathlib import Path

import pytest

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ["S3_BUCKET_MAIN"] = "local"

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


def test_document_workflow_comments_and_progress(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    doc = m.Document(doc_key=f"doc_{uid}.docx", title="Doc", status="Review")
    session.add(doc)
    session.commit()
    step1 = m.WorkflowStep(
        doc_id=doc.id,
        step_order=1,
        step_type="review",
        status="Approved",
        comment="Looks good",
    )
    step2 = m.WorkflowStep(
        doc_id=doc.id,
        step_order=2,
        step_type="approval",
        status="Pending",
    )
    session.add_all([step1, step2])
    session.commit()
    doc_id = doc.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["reader"]

    resp = client.get(f"/documents/{doc_id}/workflow")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Looks good" in html
    assert "Comment" in html
    assert 'class="progress-bar"' in html
    assert 'aria-valuenow="1"' in html
    assert 'aria-valuemax="2"' in html
