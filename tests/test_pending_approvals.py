import os
from pathlib import Path
import sys

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

# Use a separate database for these tests
_db_path = Path("test_pending.db")
if _db_path.exists():
    _db_path.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"

# Make application modules importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))

from flask import url_for
import pytest
from portal.models import SessionLocal, Document, WorkflowStep, Base, engine
from portal.app import app

# Create database schema
Base.metadata.create_all(bind=engine)

# Populate sample data
_session = SessionLocal()

assigned_doc = Document(doc_key="assigned.docx", title="Assigned Approver Doc", status="Review")
unassigned_doc = Document(doc_key="unassigned.docx", title="Unassigned Approver Doc", status="Review")
_session.add_all([assigned_doc, unassigned_doc])
_session.commit()

assigned_step = WorkflowStep(doc_id=assigned_doc.id, step_order=1, approver="approver", status="Pending")
unassigned_step = WorkflowStep(doc_id=unassigned_doc.id, step_order=1, approver=None, status="Pending")
_session.add_all([assigned_step, unassigned_step])
_session.commit()
assigned_step_id = assigned_step.id
unassigned_step_id = unassigned_step.id
_session.close()


@pytest.fixture()
def client():
    return app.test_client()


def test_pending_approvals_with_roles(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["approver"]
    resp = client.get("/dashboard/cards/pending")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    with app.test_request_context():
        assigned_url = url_for("approval_detail", id=assigned_step_id)
        unassigned_url = url_for("approval_detail", id=unassigned_step_id)
    assert "Assigned Approver Doc" in html
    assert assigned_url in html
    assert "Unassigned Approver Doc" not in html
    assert unassigned_url not in html


def test_pending_approvals_no_roles(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    resp = client.get("/dashboard/cards/pending")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    with app.test_request_context():
        assigned_url = url_for("approval_detail", id=assigned_step_id)
        unassigned_url = url_for("approval_detail", id=unassigned_step_id)
    assert "Unassigned Approver Doc" in html
    assert unassigned_url in html
    assert "Assigned Approver Doc" not in html
    assert assigned_url not in html
