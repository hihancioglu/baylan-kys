import os
import importlib
from pathlib import Path
import sys
import pytest
from unittest.mock import patch

# set up environment variables
auto_env = {
    "ONLYOFFICE_INTERNAL_URL": "http://oo",
    "ONLYOFFICE_PUBLIC_URL": "http://oo-public",
    "ONLYOFFICE_JWT_SECRET": "secret",
    "S3_ENDPOINT": "http://s3",
}
for k, v in auto_env.items():
    os.environ.setdefault(k, v)

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models():
    import importlib

    app_module = importlib.import_module("app")
    models_module = importlib.import_module("models")
    app_module.app.config["WTF_CSRF_ENABLED"] = False

    yield app_module.app, models_module

    app_module.app._got_first_request = False


@pytest.fixture()
def client(app_models):
    app, _ = app_models
    return app.test_client()


def test_assign_acknowledgements_role_targets(client, app_models):
    app, m = app_models
    m.Base.metadata.drop_all(bind=m.engine)
    m.Base.metadata.create_all(bind=m.engine)
    session = m.SessionLocal()
    publisher = m.User(username="ack_publisher")
    user1 = m.User(username="ack_user1")
    user2 = m.User(username="ack_user2")
    role = m.Role(name="ack_reader")
    session.add_all([publisher, user1, user2, role])
    session.commit()
    session.add_all([
        m.UserRole(user_id=user1.id, role_id=role.id),
        m.UserRole(user_id=user2.id, role_id=role.id),
    ])
    doc = m.Document(doc_key="ack_doc.docx", title="Ack Doc", status="Published")
    session.add(doc)
    session.commit()
    doc_id = doc.id
    publisher_id = publisher.id
    user1_id, user2_id = user1.id, user2.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        notify_mock.return_value = None
        resp = client.post(
            "/ack/assign",
            json={"doc_id": doc_id, "targets": ["ack_reader"]},
        )
        broadcast_mock.assert_called_once()

    assert resp.status_code == 200
    session = m.SessionLocal()
    acks = session.query(m.Acknowledgement).filter_by(doc_id=doc_id).all()
    ack_user_ids = {a.user_id for a in acks}
    assert ack_user_ids == {user1_id, user2_id}
    session.close()
    app._got_first_request = False


def test_assign_acknowledgements_nonexistent_doc(client, app_models):
    app, m = app_models
    m.Base.metadata.drop_all(bind=m.engine)
    m.Base.metadata.create_all(bind=m.engine)
    session = m.SessionLocal()
    publisher = m.User(username="ack_publisher")
    target = m.User(username="ack_user")
    session.add_all([publisher, target])
    session.commit()
    publisher_id = publisher.id
    target_id = target.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        resp = client.post(
            "/ack/assign", json={"doc_id": 999, "targets": [target_id]}
        )
        broadcast_mock.assert_not_called()
        notify_mock.assert_not_called()

    assert resp.status_code == 404
    assert resp.get_json()["error"] == "document not found"
    session = m.SessionLocal()
    assert session.query(m.Acknowledgement).count() == 0
    session.close()
    app._got_first_request = False


def test_assign_acknowledgements_unpublished_doc(client, app_models):
    app, m = app_models
    m.Base.metadata.drop_all(bind=m.engine)
    m.Base.metadata.create_all(bind=m.engine)
    session = m.SessionLocal()
    publisher = m.User(username="ack_publisher")
    target = m.User(username="ack_user")
    doc = m.Document(doc_key="unpub.docx", title="Unpub Doc", status="Draft")
    session.add_all([publisher, target, doc])
    session.commit()
    doc_id = doc.id
    publisher_id = publisher.id
    target_id = target.id
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        resp = client.post(
            "/ack/assign", json={"doc_id": doc_id, "targets": [target_id]}
        )
        broadcast_mock.assert_not_called()
        notify_mock.assert_not_called()

    assert resp.status_code == 400
    assert resp.get_json()["error"] == "document not published"
    session = m.SessionLocal()
    assert session.query(m.Acknowledgement).count() == 0
    session.close()
    app._got_first_request = False
