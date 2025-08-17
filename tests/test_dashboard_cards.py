import os
from pathlib import Path
import sys

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

db_path = Path("test.db")
if db_path.exists():
    db_path.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "portal"))

from flask import url_for
import pytest

import importlib
import models as m
import app as a
importlib.reload(m)
importlib.reload(a)
SessionLocal = m.SessionLocal
Document = m.Document
WorkflowStep = m.WorkflowStep
DocumentRevision = m.DocumentRevision
User = m.User
Base = m.Base
engine = m.engine
app = a.app


# Create database schema
Base.metadata.create_all(bind=engine)

# Populate sample data
session = SessionLocal()

# Create a user to assign approval steps
user = User(username="approver")
session.add(user)
session.commit()

# Document needing approval
pending_doc = Document(doc_key="pending.docx", title="Pending Doc", status="Review")
# Document for mandatory reading
mandatory_doc = Document(doc_key="mandatory.docx", title="Mandatory Doc", status="Published")
# Document with recent revision
recent_doc = Document(doc_key="recent.docx", title="Recent Doc", status="Published")

session.add_all([pending_doc, mandatory_doc, recent_doc])
session.commit()

step = WorkflowStep(doc_id=pending_doc.id, step_order=1, user_id=user.id, status="Pending")
revision = DocumentRevision(doc_id=recent_doc.id, major_version=1, minor_version=0)

session.add_all([step, revision])
session.commit()
step_id = step.id
revision_id = revision.id
pending_doc_id = pending_doc.id
mandatory_doc_id = mandatory_doc.id
recent_doc_id = recent_doc.id
session.close()


@pytest.fixture()
def client():
    return app.test_client()


def test_dashboard_card_endpoints(client):
    import importlib, models as m, app as a
    importlib.reload(m)
    importlib.reload(a)
    global SessionLocal, Document, WorkflowStep, DocumentRevision, User, Base, engine, app, step_id, revision_id, mandatory_doc_id, recent_doc_id, pending_doc_id
    SessionLocal = m.SessionLocal
    Document = m.Document
    WorkflowStep = m.WorkflowStep
    DocumentRevision = m.DocumentRevision
    User = m.User
    Base = m.Base
    engine = m.engine
    app = a.app

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    user = User(username="approver")
    session.add(user)
    session.commit()
    pending_doc = Document(doc_key="pending.docx", title="Pending Doc", status="Review")
    mandatory_doc = Document(doc_key="mandatory.docx", title="Mandatory Doc", status="Published")
    recent_doc = Document(doc_key="recent.docx", title="Recent Doc", status="Published")
    session.add_all([pending_doc, mandatory_doc, recent_doc])
    session.commit()
    step = WorkflowStep(doc_id=pending_doc.id, step_order=1, user_id=user.id, status="Pending")
    revision = DocumentRevision(doc_id=recent_doc.id, major_version=1, minor_version=0)
    session.add_all([step, revision])
    session.commit()
    step_id = step.id
    revision_id = revision.id
    pending_doc_id = pending_doc.id
    mandatory_doc_id = mandatory_doc.id
    recent_doc_id = recent_doc.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["approver", "reader"]

    # Pending approvals
    resp = client.get(
        "/api/dashboard/cards/pending", headers={"HX-Request": "true"}
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    with app.test_request_context():
        pending_url = url_for("approval_detail", id=step_id)
    assert pending_url in html

    # Mandatory reading
    resp = client.get(
        "/api/dashboard/cards/mandatory", headers={"HX-Request": "true"}
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    with app.test_request_context():
        mandatory_url = url_for("document_detail", doc_id=mandatory_doc_id)
    assert "Mandatory Doc" in html
    assert mandatory_url in html

    # Recent revisions
    resp = client.get(
        "/api/dashboard/cards/recent", headers={"HX-Request": "true"}
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    with app.test_request_context():
        recent_url = url_for(
            "document_detail", doc_id=recent_doc_id, revision_id=revision_id
        )
    assert "Recent Doc" in html
    assert recent_url in html

    # Dashboard main page loads successfully
    resp = client.get("/")
    assert resp.status_code == 200
