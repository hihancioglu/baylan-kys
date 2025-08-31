import importlib
import sys
from unittest.mock import MagicMock

from sqlalchemy.orm import sessionmaker


def _create_user(models, user_id: int) -> None:
    Session = sessionmaker(bind=models.engine)
    sess = Session()
    sess.add(models.User(id=user_id, username=f"u{user_id}", email="u@example.com"))
    sess.commit()
    sess.close()


def _setup_queue(monkeypatch):
    rq = importlib.import_module("rq_stub")
    monkeypatch.setitem(sys.modules, "rq", rq)
    notifications = importlib.reload(importlib.import_module("notifications"))
    q = rq.Queue("notifications")
    monkeypatch.setattr(notifications, "queue", q)
    return q, notifications, rq.SimpleWorker


def test_one_notifier_failure_does_not_block_others(monkeypatch):
    models = importlib.import_module("models")
    _create_user(models, 101)

    notifications = importlib.import_module("notifications")

    fail_notifier = MagicMock()
    fail_notifier.send.side_effect = Exception("boom")
    success_notifier = MagicMock()

    monkeypatch.setattr(
        notifications,
        "_load_notifiers",
        lambda: [("fail", fail_notifier), ("success", success_notifier)],
    )
    monkeypatch.delenv("ENABLE_WEBHOOK_NOTIFIER", raising=False)

    notifications._send_notification(101, "Sub", "Body")

    assert fail_notifier.send.called
    assert success_notifier.send.called


def test_all_notifiers_fail_triggers_retry(monkeypatch):
    q, notifications, SimpleWorker = _setup_queue(monkeypatch)

    models = importlib.import_module("models")
    _create_user(models, 102)

    n1 = MagicMock()
    n1.send.side_effect = [Exception("fail1"), None]
    n2 = MagicMock()
    n2.send.side_effect = [Exception("fail2"), None]

    monkeypatch.setattr(
        notifications,
        "_load_notifiers",
        lambda: [("n1", n1), ("n2", n2)],
    )
    monkeypatch.delenv("ENABLE_WEBHOOK_NOTIFIER", raising=False)

    notifications.notify_user(102, "Subject", "Body")
    worker = SimpleWorker([q])
    worker.work(burst=True)

    assert n1.send.call_count == 2
    assert n2.send.call_count == 2
