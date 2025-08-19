import os
from pathlib import Path
import sys

import pytest

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

# Make application modules importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


def get_models():
    import models as m
    return m


def get_app_module():
    import app as a
    return a


@pytest.fixture(autouse=True)
def models(reset_database):
    m = get_models()
    m.seed_documents()
    SessionLocal = m.SessionLocal
    Document = m.Document
    WorkflowStep = m.WorkflowStep
    Acknowledgement = m.Acknowledgement
    User = m.User

    session = SessionLocal()
    user = User(username="tester", email="tester@example.com")
    session.add(user)
    session.commit()

    docs = {d.code: d for d in session.query(Document).all()}
    # Publish documents for mandatory reading
    docs["SD1"].status = "Published"
    docs["SD3"].status = "Published"
    session.commit()

    # Pending approval steps for two documents with different standards
    step1 = WorkflowStep(
        doc_id=docs["SD1"].id,
        step_order=1,
        user_id=user.id,
        status="Pending",
        step_type="approval",
    )
    step3 = WorkflowStep(
        doc_id=docs["SD3"].id,
        step_order=1,
        user_id=user.id,
        status="Pending",
        step_type="approval",
    )
    session.add_all([step1, step3])

    # Mandatory reading acknowledgements
    ack1 = Acknowledgement(user_id=user.id, doc_id=docs["SD1"].id)
    ack3 = Acknowledgement(user_id=user.id, doc_id=docs["SD3"].id)
    session.add_all([ack1, ack3])
    session.commit()
    session.close()
    return m


@pytest.fixture()
def app_module(models):
    return get_app_module()


@pytest.fixture()
def client(app_module):
    return app_module.app.test_client()


def test_pending_approvals_filtered_by_standard(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/pending-approvals?standard=ISO9001")
    assert resp.status_code == 200
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0][0] == "Seeded Document 1"


def test_mandatory_reading_filtered_by_standard(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/api/dashboard/mandatory-reading?standard=ISO14001")
    assert resp.status_code == 200
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0][0] == "Seeded Document 3"


def test_reports_standard_summary_counts(client, app_module):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = [app_module.RoleEnum.AUDITOR.value]
    resp = client.get("/reports/standard-summary?format=json")
    assert resp.status_code == 200
    data = resp.get_json()
    result = {d["standard"]: d["count"] for d in data}
    assert result == {"ISO9001": 2, "ISO27001": 1, "ISO14001": 1}
