import os
import sys
import importlib
from pathlib import Path

import pytest


@pytest.fixture()
def setup_data():
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(repo_root / "portal"))
    models = importlib.import_module("models")
    session = models.SessionLocal()
    user = models.User(username="approver1")
    session.add(user)
    session.commit()
    doc = models.Document(doc_key="doc.docx", title="Doc", status="Review")
    session.add(doc)
    session.commit()
    step = models.WorkflowStep(
        doc_id=doc.id,
        step_order=1,
        user_id=user.id,
        status="Pending",
        step_type="approval",
    )
    session.add(step)
    session.commit()
    session.close()
    yield


def test_pending_approvals_report(setup_data):
    reports = importlib.import_module("reports")
    rows = reports.pending_approvals_report()
    assert len(rows) == 1
    assert rows[0]["document"] == "Doc"
    assert rows[0]["approver"] == "approver1"
