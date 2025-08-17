import importlib
import os
import sys
from pathlib import Path

import pytest
from flask import url_for


@pytest.fixture
def app_models(tmp_path):
    os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
    os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
    os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
    os.environ.setdefault("S3_ENDPOINT", "http://s3")

    db_path = tmp_path / "test.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    repo_root = Path(__file__).resolve().parent.parent
    portal_path = repo_root / "portal"
    sys.path.insert(0, str(portal_path))

    import models as m
    import app as a
    m = importlib.reload(m)
    a = importlib.reload(a)

    m.Base.metadata.create_all(bind=m.engine)
    session = m.SessionLocal()

    user = m.User(username="approver")
    session.add(user)
    session.commit()

    pending_doc = m.Document(
        doc_key="pending.docx", title="Pending Doc", status="Review"
    )
    mandatory_doc = m.Document(
        doc_key="mandatory.docx", title="Mandatory Doc", status="Published"
    )
    recent_doc = m.Document(
        doc_key="recent.docx", title="Recent Doc", status="Published"
    )
    session.add_all([pending_doc, mandatory_doc, recent_doc])
    session.commit()

    step = m.WorkflowStep(
        doc_id=pending_doc.id,
        step_order=1,
        user_id=user.id,
        status="Pending",
        step_type="approval",
    )
    revision = m.DocumentRevision(
        doc_id=recent_doc.id, major_version=1, minor_version=0
    )
    session.add_all([step, revision])
    session.commit()

    data = {
        "app": a.app,
        "models": m,
        "step_id": step.id,
        "revision_id": revision.id,
        "pending_doc_id": pending_doc.id,
        "mandatory_doc_id": mandatory_doc.id,
        "recent_doc_id": recent_doc.id,
    }
    session.close()

    try:
        yield data
    finally:
        m.Base.metadata.drop_all(bind=m.engine)
        if db_path.exists():
            db_path.unlink()
        if str(portal_path) in sys.path:
            sys.path.remove(str(portal_path))


@pytest.fixture
def client(app_models):
    return app_models["app"].test_client()


def test_dashboard_card_endpoints(app_models, client):
    app = app_models["app"]
    step_id = app_models["step_id"]
    revision_id = app_models["revision_id"]
    pending_doc_id = app_models["pending_doc_id"]
    mandatory_doc_id = app_models["mandatory_doc_id"]
    recent_doc_id = app_models["recent_doc_id"]

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["approver", "reader"]

    # Pending approvals
    resp = client.get("/api/dashboard/cards/pending", headers={"HX-Request": "true"})
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
    resp = client.get("/api/dashboard/cards/recent", headers={"HX-Request": "true"})
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

