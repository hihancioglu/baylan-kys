import importlib
import os
from pathlib import Path
import sys

import pytest

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def models():
    models_module = importlib.reload(importlib.import_module("models"))
    models_module.Base.metadata.create_all(bind=models_module.engine)
    return models_module


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
