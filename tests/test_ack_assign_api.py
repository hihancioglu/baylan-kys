import os
import importlib
from pathlib import Path
import sys
import uuid
import json

import pytest
from unittest.mock import patch

# set up environment variables
auto_env = {
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
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    publisher = m.User(username=f"ack_publisher_{uid}")
    user1 = m.User(username=f"ack_user1_{uid}")
    user2 = m.User(username=f"ack_user2_{uid}")
    role = m.Role(name=f"ack_reader_{uid}")
    session.add_all([publisher, user1, user2, role])
    session.commit()
    user1.roles.append(role)
    user2.roles.append(role)
    doc = m.Document(doc_key=f"ack_doc_{uid}.docx", title="Ack Doc", status="Published")
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
            "/api/ack/assign",
            json={"doc_id": doc_id, "targets": [f"ack_reader_{uid}"]},
        )
        broadcast_mock.assert_called_once()
    assert resp.status_code == 200
    trigger = json.loads(resp.headers.get("HX-Trigger"))
    assert trigger.get("ackUpdated") is True
    assert trigger.get("showToast") == "Assignments added"
    session = m.SessionLocal()
    acks = session.query(m.Acknowledgement).filter_by(doc_id=doc_id).all()
    ack_user_ids = {a.user_id for a in acks}
    assert ack_user_ids == {user1_id, user2_id}
    session.close()
    app._got_first_request = False


def test_assign_acknowledgements_nonexistent_doc(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    publisher = m.User(username=f"ack_publisher_{uid}")
    target = m.User(username=f"ack_user_{uid}")
    session.add_all([publisher, target])
    session.commit()
    publisher_id = publisher.id
    target_id = target.id
    initial_count = session.query(m.Acknowledgement).count()
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        resp = client.post(
            "/api/ack/assign", json={"doc_id": 999, "targets": [target_id]}
        )
        broadcast_mock.assert_not_called()
        notify_mock.assert_not_called()

    assert resp.status_code == 404
    assert resp.get_json()["error"] == "document not found"
    session = m.SessionLocal()
    assert session.query(m.Acknowledgement).count() == initial_count
    session.close()
    app._got_first_request = False


def test_assign_acknowledgements_unpublished_doc(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    publisher = m.User(username=f"ack_publisher_{uid}")
    target = m.User(username=f"ack_user_{uid}")
    doc = m.Document(doc_key=f"unpub_{uid}.docx", title="Unpub Doc", status="Draft")
    session.add_all([publisher, target, doc])
    session.commit()
    doc_id = doc.id
    publisher_id = publisher.id
    target_id = target.id
    initial_count = session.query(m.Acknowledgement).count()
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        resp = client.post(
            "/api/ack/assign", json={"doc_id": doc_id, "targets": [target_id]}
        )
        broadcast_mock.assert_not_called()
        notify_mock.assert_not_called()

    assert resp.status_code == 400
    assert resp.get_json()["error"] == "document not published"
    session = m.SessionLocal()
    assert session.query(m.Acknowledgement).count() == initial_count
    session.close()
    app._got_first_request = False


def test_assign_acknowledgements_user_targets(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    publisher = m.User(username=f"ack_publisher_{uid}")
    user1 = m.User(username=f"ack_user1_{uid}")
    user2 = m.User(username=f"ack_user2_{uid}")
    doc = m.Document(doc_key=f"ack_doc_{uid}.docx", title="Ack Doc", status="Published")
    session.add_all([publisher, user1, user2, doc])
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
            "/api/ack/assign", json={"doc_id": doc_id, "targets": [user1_id, user2_id]}
        )
        broadcast_mock.assert_called_once()
        notify_mock.assert_called_once()

    assert resp.status_code == 200
    session = m.SessionLocal()
    acks = session.query(m.Acknowledgement).filter_by(doc_id=doc_id).all()
    ack_user_ids = {a.user_id for a in acks}
    assert ack_user_ids == {user1_id, user2_id}
    session.close()
    app._got_first_request = False


def test_assign_acknowledgements_missing_doc_id(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    publisher = m.User(username=f"ack_publisher_{uid}")
    user = m.User(username=f"ack_user_{uid}")
    session.add_all([publisher, user])
    session.commit()
    publisher_id = publisher.id
    user_id = user.id
    initial_count = session.query(m.Acknowledgement).count()
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        resp = client.post("/api/ack/assign", json={"targets": [user_id]})
        broadcast_mock.assert_not_called()
        notify_mock.assert_not_called()

    assert resp.status_code == 400
    assert resp.get_json()["error"] == "doc_id required"
    session = m.SessionLocal()
    assert session.query(m.Acknowledgement).count() == initial_count
    session.close()
    app._got_first_request = False


def test_assign_acknowledgements_invalid_targets(client, app_models):
    app, m = app_models
    session = m.SessionLocal()
    uid = uuid.uuid4().hex
    publisher = m.User(username=f"ack_publisher_{uid}")
    doc = m.Document(doc_key=f"ack_doc_{uid}.docx", title="Ack Doc", status="Published")
    session.add_all([publisher, doc])
    session.commit()
    doc_id = doc.id
    publisher_id = publisher.id
    initial_count = session.query(m.Acknowledgement).count()
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = ["publisher"]

    with patch("app.broadcast_counts") as broadcast_mock, patch(
        "app.notify_mandatory_read"
    ) as notify_mock:
        resp = client.post(
            "/api/ack/assign", json={"doc_id": doc_id, "targets": ["bogus_role"]}
        )
        broadcast_mock.assert_called_once()
        notify_mock.assert_not_called()

    assert resp.status_code == 200
    session = m.SessionLocal()
    assert session.query(m.Acknowledgement).count() == initial_count
    session.close()
    app._got_first_request = False
