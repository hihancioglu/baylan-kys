import os
import importlib
from pathlib import Path
import sys
import re
import pytest

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


def test_modal_ids_unique(client, app_models):
    _, m = app_models
    session = m.SessionLocal()
    user = m.User(username="approver")
    doc1 = m.Document(doc_key="doc1.docx", title="Doc1", status="Review")
    doc2 = m.Document(doc_key="doc2.docx", title="Doc2", status="Review")
    session.add_all([user, doc1, doc2])
    session.commit()
    step1 = m.WorkflowStep(doc_id=doc1.id, step_order=1, user_id=user.id, status="Pending", step_type="approval")
    step2 = m.WorkflowStep(doc_id=doc2.id, step_order=1, user_id=user.id, status="Pending", step_type="approval")
    session.add_all([step1, step2])
    session.commit()
    user_id = user.id
    step1_id = step1.id
    step2_id = step2.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": user_id}
        sess["roles"] = ["approver"]

    resp = client.get("/approvals")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    for sid in (step1_id, step2_id):
        assert html.count(f'id="step-{sid}-approve-modal"') == 1
        assert html.count(f'id="step-{sid}-reject-modal"') == 1
        assert html.count(f'id="step-{sid}-reassign-modal"') == 1
        assert html.count(f'data-bs-target="#step-{sid}-reassign-modal"') == 1

    modal_ids = re.findall(r'id="(step-\d+-(?:approve|reject|reassign)-modal)"', html)
    assert len(modal_ids) == len(set(modal_ids))
