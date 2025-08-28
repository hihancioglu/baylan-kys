import importlib
import sys
from unittest.mock import patch

from sqlalchemy.orm import sessionmaker


def _setup_queue(monkeypatch):
    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
    notifications = importlib.reload(importlib.import_module("notifications"))
    q = rq.Queue("notifications")
    monkeypatch.setattr(notifications, "queue", q)
    return q, notifications, rq.SimpleWorker


def test_notify_user_enqueues_job(monkeypatch):
    q, notifications, _ = _setup_queue(monkeypatch)
    notifications.notify_user(1, "Subject", "Body")
    assert len(q.jobs) == 1


def test_notification_retry_on_failure(monkeypatch):
    q, notifications, SimpleWorker = _setup_queue(monkeypatch)

    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    sess = Session()
    sess.add(models.User(id=1, username="u1", email="user@example.com"))
    sess.commit()
    sess.close()

    with patch.object(
        notifications.EmailNotifier,
        "send",
        side_effect=[Exception("boom"), None],
    ) as mock_send:
        notifications.notify_user(1, "Sub", "Body")
        worker = SimpleWorker([q])
        worker.work(burst=True)
        assert mock_send.call_count == 2

