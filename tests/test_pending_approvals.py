import os
import sys
from pathlib import Path
import importlib

from flask import url_for
import pytest

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")


@pytest.fixture()
def setup_data():
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(repo_root / "portal"))
    models = importlib.import_module("models")
    app_module = importlib.import_module("app")
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    session = models.SessionLocal()
    user1 = models.User(username="approver1")
    user2 = models.User(username="approver2")
    session.add_all([user1, user2])
    session.commit()
    assigned_doc = models.Document(
        doc_key="assigned.docx", title="Assigned Approver Doc", status="Review"
    )
    unassigned_doc = models.Document(
        doc_key="unassigned.docx", title="Unassigned Approver Doc", status="Review"
    )
    session.add_all([assigned_doc, unassigned_doc])
    session.commit()
    assigned_step = models.WorkflowStep(
        doc_id=assigned_doc.id,
        step_order=1,
        user_id=user1.id,
        status="Pending",
        step_type="approval",
    )
    unassigned_step = models.WorkflowStep(
        doc_id=unassigned_doc.id,
        step_order=1,
        user_id=None,
        status="Pending",
        step_type="approval",
    )
    session.add_all([assigned_step, unassigned_step])
    session.commit()
    ids = {
        "user1": user1.id,
        "user2": user2.id,
        "assigned_step": assigned_step.id,
        "unassigned_step": unassigned_step.id,
    }
    session.close()
    yield app_module.app, ids


@pytest.fixture()
def client(setup_data):
    app, _ = setup_data
    return app.test_client()


def test_pending_approvals_for_assigned_user(client, setup_data):
    app, ids = setup_data
    with client.session_transaction() as sess:
        sess["user"] = {"id": ids["user1"], "name": "Tester"}
        sess["roles"] = []
    resp = client.get(
        "/api/dashboard/cards/pending", headers={"HX-Request": "true"}
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    with app.test_request_context():
        assigned_url = url_for("approval_detail", id=ids["assigned_step"])
        unassigned_url = url_for("approval_detail", id=ids["unassigned_step"])
    assert "Assigned Approver Doc" in html
    assert assigned_url in html
    assert "Unassigned Approver Doc" not in html
    assert unassigned_url not in html


def test_pending_approvals_other_user(client, setup_data):
    app, ids = setup_data
    with client.session_transaction() as sess:
        sess["user"] = {"id": ids["user2"], "name": "Tester2"}
        sess["roles"] = []
    resp = client.get(
        "/api/dashboard/cards/pending", headers={"HX-Request": "true"}
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    with app.test_request_context():
        assigned_url = url_for("approval_detail", id=ids["assigned_step"])
        unassigned_url = url_for("approval_detail", id=ids["unassigned_step"])
    assert "Assigned Approver Doc" not in html
    assert assigned_url not in html
    assert "Unassigned Approver Doc" not in html
    assert unassigned_url not in html

