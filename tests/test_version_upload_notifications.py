import importlib
import io
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock


def _setup_app(monkeypatch):
    repo_root = Path(__file__).resolve().parent.parent
    os.environ.setdefault("S3_ENDPOINT", "http://s3")
    os.environ["DATABASE_URL"] = f"sqlite:///{repo_root / 'test.db'}"
    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
    app_module = importlib.reload(importlib.import_module("app"))
    notifications = importlib.reload(importlib.import_module("notifications"))
    storage = importlib.import_module("storage")

    q = rq.Queue("notifications")
    monkeypatch.setattr(notifications, "queue", q)
    app_module.notify_version_uploaded = notifications.notify_version_uploaded
    storage.storage_client.put = MagicMock()
    app_module.enqueue_preview = lambda *args, **kwargs: None
    app_module.app.config["WTF_CSRF_ENABLED"] = False

    return app_module, notifications, q


def test_version_upload_enqueues_notifications(monkeypatch):
    app_module, notifications, q = _setup_app(monkeypatch)
    models = importlib.import_module("models")

    session = models.SessionLocal()
    owner = models.User(username="owner")
    subscriber = models.User(username="sub")
    doc = models.Document(doc_key="d1", title="Doc1", owner=owner)
    session.add_all([owner, subscriber, doc])
    session.commit()
    owner_id = owner.id
    subscriber_id = subscriber.id
    doc_id = doc.id
    session.add(models.Acknowledgement(user_id=subscriber_id, doc_id=doc_id))
    session.commit()
    session.close()

    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": owner_id}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    data = {"file": (io.BytesIO(b"data"), "f.pdf", "application/pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code in (200, 201)
    assert len(q.jobs) == 2
