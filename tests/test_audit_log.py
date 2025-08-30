import importlib
import os
from pathlib import Path
import sys

import pytest

os.environ.setdefault("S3_ENDPOINT", "http://s3")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def models():
    models_module = importlib.reload(importlib.import_module("models"))
    models_module.Base.metadata.create_all(bind=models_module.engine)
    return models_module


@pytest.fixture()
def app_models():
    app_module = importlib.reload(importlib.import_module("app"))
    models_module = importlib.reload(importlib.import_module("models"))
    models_module.Base.metadata.create_all(bind=models_module.engine)
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module, models_module


def test_document_crud_logs(models):
    m = models
    session = m.SessionLocal()
    doc = m.Document(doc_key="doc.log", title="Log Doc")
    session.add(doc)
    session.commit()
    doc_id = doc.id

    logs = session.query(m.AuditLog).filter_by(entity_type="Document", entity_id=doc_id, action="create").all()
    assert len(logs) == 1
    assert logs[0].payload["title"] == "Log Doc"

    doc.title = "Updated"
    session.commit()
    logs = session.query(m.AuditLog).filter_by(entity_type="Document", entity_id=doc_id, action="update").all()
    assert len(logs) == 1
    assert logs[0].payload["changes"]["title"]["old"] == "Log Doc"
    assert logs[0].payload["changes"]["title"]["new"] == "Updated"

    session.delete(doc)
    session.commit()
    logs = session.query(m.AuditLog).filter_by(entity_type="Document", entity_id=doc_id, action="delete").all()
    assert len(logs) == 1
    session.close()


def test_workflow_step_comment_log(models):
    m = models
    session = m.SessionLocal()
    doc = m.Document(doc_key="wf.doc", title="WF Doc")
    session.add(doc)
    session.commit()
    step = m.WorkflowStep(doc_id=doc.id, step_order=1, status="Pending")
    session.add(step)
    session.commit()
    step_id = step.id

    step.comment = "Needs changes"
    session.commit()
    logs = session.query(m.AuditLog).filter_by(entity_type="WorkflowStep", entity_id=step_id, action="comment").all()
    assert len(logs) == 1
    assert logs[0].payload["comment"] == "Needs changes"
    session.close()


def test_dif_workflow_step_logs(models):
    m = models
    session = m.SessionLocal()

    user = m.User(username="req", email="req@example.com")
    session.add(user)
    session.commit()

    dif = m.DifRequest(subject="Subject", requester_id=user.id)
    session.add(dif)
    session.commit()

    step = m.DifWorkflowStep(dif_id=dif.id, role="reviewer", step_order=1, status="Pending")
    session.add(step)
    session.commit()

    step_id = step.id

    logs = session.query(m.AuditLog).filter_by(entity_type="DifWorkflowStep", entity_id=step_id, action="create").all()
    assert len(logs) == 1

    step.comment = "Looks good"
    session.commit()
    logs = session.query(m.AuditLog).filter_by(entity_type="DifWorkflowStep", entity_id=step_id, action="comment").all()
    assert len(logs) == 1
    assert logs[0].payload["comment"] == "Looks good"

    session.delete(step)
    session.commit()
    logs = session.query(m.AuditLog).filter_by(entity_type="DifWorkflowStep", entity_id=step_id, action="delete").all()
    assert len(logs) == 1
    session.close()


def test_dif_request_crud_logs(models):
    m = models
    session = m.SessionLocal()

    user = m.User(username="req2", email="req2@example.com")
    session.add(user)
    session.commit()

    dif = m.DifRequest(subject="Initial", requester_id=user.id)
    session.add(dif)
    session.commit()
    dif_id = dif.id

    logs = session.query(m.AuditLog).filter_by(entity_type="DifRequest", entity_id=dif_id, action="create").all()
    assert len(logs) == 1

    dif.subject = "Updated"
    session.commit()
    logs = session.query(m.AuditLog).filter_by(entity_type="DifRequest", entity_id=dif_id, action="update").all()
    assert len(logs) == 1
    assert logs[0].payload["changes"]["subject"]["old"] == "Initial"
    assert logs[0].payload["changes"]["subject"]["new"] == "Updated"

    session.delete(dif)
    session.commit()
    logs = session.query(m.AuditLog).filter_by(entity_type="DifRequest", entity_id=dif_id, action="delete").all()
    assert len(logs) == 1
    session.close()


def test_create_document_api_logs_once(app_models):
    app_module, models = app_models
    from unittest.mock import MagicMock
    storage = importlib.import_module("storage")
    storage.storage_client.head_object = MagicMock(return_value={})
    app_module.extract_text = lambda key: ""
    app_module.notify_mandatory_read = lambda doc, users: None
    app_module.index_document = lambda doc, content: None

    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    first = list(app_module.STANDARD_MAP.keys())[0]
    payload = {
        "code": "DOC_API",
        "title": "API Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "uploaded_file_key": "key123",
        "uploaded_file_name": "file.txt",
        "standard": first,
    }
    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 201
    doc_id = resp.get_json()["id"]

    session = models.SessionLocal()
    logs = (
        session.query(models.AuditLog)
        .filter_by(entity_type="Document", entity_id=doc_id)
        .all()
    )
    assert len(logs) == 1
    assert logs[0].action == "create"
    session.close()
