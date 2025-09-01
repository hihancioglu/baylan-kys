import importlib
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock


def _setup_app(monkeypatch):
    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
    app_module = importlib.reload(importlib.import_module("app"))
    notifications = importlib.reload(importlib.import_module("notifications"))
    q = rq.Queue("notifications")
    monkeypatch.setattr(notifications, "queue", q)
    app_module.notify_user = notifications.notify_user
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module, notifications, q


def test_checkout_sends_notifications(monkeypatch):
    app_module, notifications, q = _setup_app(monkeypatch)
    models = importlib.import_module("models")

    session = models.SessionLocal()
    role = models.Role(name="r")
    owner = models.User(username="owner", email="o@example.com")
    previous = models.User(username="prev", email="p@example.com")
    actor = models.User(username="actor", email="a@example.com")
    actor.roles.append(role)
    session.add_all([role, owner, previous, actor])
    session.commit()
    owner_id, previous_id, actor_id = owner.id, previous.id, actor.id
    doc = models.Document(
        doc_key="d1",
        title="Doc1",
        owner_id=owner_id,
        locked_by=previous_id,
        lock_expires_at=datetime.utcnow() - timedelta(minutes=1),
    )
    session.add(doc)
    session.add(models.UserSetting(user_id=owner_id, email_enabled=True))
    session.add(models.UserSetting(user_id=previous_id, email_enabled=False))
    session.commit()
    session.add(
        models.DocumentPermission(role_id=role.id, doc_id=doc.id, can_checkout=True, can_checkin=True)
    )
    session.commit()
    doc_id = doc.id
    session.close()

    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": actor_id, "name": "Actor"}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    resp = client.post(f"/api/documents/{doc_id}/checkout")
    assert resp.status_code == 200
    assert {job.args[0] for job in q.jobs} == {owner_id, previous_id}

    monkeypatch.setattr(
        notifications, "_load_notifiers", lambda: [("email", notifications.EmailNotifier())]
    )
    send_mock = MagicMock()
    monkeypatch.setattr(notifications.EmailNotifier, "send", send_mock)

    for job in q.jobs:
        job.perform()

    send_mock.assert_called_once()
    assert send_mock.call_args[0][0].id == owner_id
