import importlib
from unittest.mock import patch

from sqlalchemy.orm import sessionmaker


def _create_user(models, *, user_id: int, url: str | None) -> None:
    Session = sessionmaker(bind=models.engine)
    sess = Session()
    sess.add(models.User(id=user_id, username=f"u{user_id}"))
    sess.add(
        models.UserSetting(
            user_id=user_id, webhook_enabled=True, webhook_url=url
        )
    )
    sess.commit()
    sess.close()


def test_webhook_uses_user_url(monkeypatch):
    models = importlib.import_module("models")
    _create_user(models, user_id=2001, url="http://example.com/hook")

    monkeypatch.setenv("ENABLE_WEBHOOK_NOTIFIER", "1")
    notifications = importlib.reload(importlib.import_module("notifications"))
    monkeypatch.setattr(notifications, "_load_notifiers", lambda: [])

    with patch.object(notifications.requests, "post") as mock_post:
        notifications._send_notification(2001, "Sub", "Body")

    mock_post.assert_called_once_with(
        "http://example.com/hook",
        json={"user_id": 2001, "subject": "Sub", "body": "Body"},
    )


def test_webhook_uses_default_url(monkeypatch):
    models = importlib.import_module("models")
    _create_user(models, user_id=2002, url=None)

    monkeypatch.setenv("ENABLE_WEBHOOK_NOTIFIER", "1")
    monkeypatch.setenv("WEBHOOK_URL_DEFAULT", "http://default/hook")
    notifications = importlib.reload(importlib.import_module("notifications"))
    monkeypatch.setattr(notifications, "_load_notifiers", lambda: [])

    with patch.object(notifications.requests, "post") as mock_post:
        notifications._send_notification(2002, "Subject", "Body")

    mock_post.assert_called_once_with(
        "http://default/hook",
        json={"user_id": 2002, "subject": "Subject", "body": "Body"},
    )

