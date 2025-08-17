import os
import importlib
from pathlib import Path
import sys
import pytest
from unittest.mock import patch

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

_db_path = Path("test_publish_document.db")
if _db_path.exists():
    _db_path.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"

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


def test_publish_assigns_acknowledgements(client, app_models):
    app, m = app_models
    m.Base.metadata.drop_all(bind=m.engine)
    m.Base.metadata.create_all(bind=m.engine)
    session = m.SessionLocal()
    publisher = m.User(username="publisher")
    user1 = m.User(username="user1")
    user2 = m.User(username="user2")
    user3 = m.User(username="user3")
    role = m.Role(name="reader")
    session.add_all([publisher, user1, user2, user3, role])
    session.commit()
    session.add_all([
        m.UserRole(user_id=user2.id, role_id=role.id),
        m.UserRole(user_id=user3.id, role_id=role.id),
    ])
    doc = m.Document(doc_key="doc.docx", title="Doc", status="Approved")
    session.add(doc)
    session.commit()
    doc_id = doc.id
    publisher_id = publisher.id
    user1_id, user2_id, user3_id = user1.id, user2.id, user3.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        notify_mock.return_value = None
        resp = client.post(
            f"/api/documents/{doc_id}/publish",
            data={"users": [str(user1_id)], "roles": ["reader"]},
        )
        broadcast_mock.assert_called_once()

    assert resp.status_code == 302
    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.status == "Published"
    acks = session.query(m.Acknowledgement).filter_by(doc_id=doc_id).all()
    ack_user_ids = {a.user_id for a in acks}
    assert ack_user_ids == {user1_id, user2_id, user3_id}
    session.close()


def test_publish_rejects_unapproved_document(client, app_models):
    app, m = app_models
    m.Base.metadata.drop_all(bind=m.engine)
    m.Base.metadata.create_all(bind=m.engine)
    session = m.SessionLocal()
    publisher = m.User(username="publisher")
    doc = m.Document(doc_key="doc.docx", title="Doc", status="Draft")
    session.add_all([publisher, doc])
    session.commit()
    doc_id = doc.id
    publisher_id = publisher.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    resp = client.post(f"/api/documents/{doc_id}/publish", data={})
    assert resp.status_code == 400
    session = m.SessionLocal()
    doc = session.get(m.Document, doc_id)
    assert doc.status == "Draft"
    session.close()
