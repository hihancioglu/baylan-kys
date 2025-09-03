import importlib
import json
import sys
from pathlib import Path


def _setup_app(monkeypatch):
    repo_root = Path(__file__).resolve().parent.parent
    monkeypatch.setenv("S3_ENDPOINT", "http://s3")
    models = importlib.import_module("models")
    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
    notifications = importlib.reload(importlib.import_module("notifications"))
    app_module = importlib.reload(importlib.import_module("app"))
    q = rq.Queue("notifications")
    monkeypatch.setattr(notifications, "queue", q)
    app_module.notify_document_approved = notifications.notify_document_approved
    app_module.notify_document_published = notifications.notify_document_published
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    models.Base.metadata.create_all(bind=models.engine)
    return app_module, models, q


def test_document_approval_queues_notification(monkeypatch):
    app_module, models, q = _setup_app(monkeypatch)
    session = models.SessionLocal()
    owner = models.User(username="owner")
    approver = models.User(username="approver")
    doc = models.Document(doc_key="doc1", title="Doc1", status="Review", owner=owner)
    session.add_all([owner, approver, doc])
    session.commit()
    step = models.WorkflowStep(doc_id=doc.id, step_order=1, user_id=approver.id, status="Pending")
    session.add(step)
    session.commit()
    owner_id = owner.id
    step_id = step.id
    approver_id = approver.id
    session.close()
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = [app_module.RoleEnum.APPROVER.value]
    resp = client.post(f"/api/approvals/{step_id}/approve", json={})
    assert resp.status_code == 200
    assert len(q.jobs) == 1
    assert q.jobs[0].args[0] == owner_id


def test_publish_document_queues_notification(monkeypatch):
    app_module, models, q = _setup_app(monkeypatch)
    session = models.SessionLocal()
    owner = models.User(username="owner")
    publisher = models.User(username="publisher")
    doc = models.Document(doc_key="doc1", title="Doc1", status="Approved", owner=owner)
    session.add_all([owner, publisher, doc])
    session.commit()
    doc_id = doc.id
    owner_id = owner.id
    publisher_id = publisher.id
    session.close()
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = [app_module.RoleEnum.PUBLISHER.value]
    resp = client.post(
        f"/api/documents/{doc_id}/publish", data={}, headers={"HX-Request": "true"}
    )
    assert resp.status_code == 204
    assert resp.headers["HX-Trigger"] == json.dumps({"showToast": "Document published"})
    assert len(q.jobs) == 1
    assert q.jobs[0].args[0] == owner_id


def test_publish_review_document_queues_notification(monkeypatch):
    app_module, models, q = _setup_app(monkeypatch)
    session = models.SessionLocal()
    owner = models.User(username="owner")
    publisher = models.User(username="publisher")
    doc = models.Document(doc_key="doc1", title="Doc1", status="Review", owner=owner)
    session.add_all([owner, publisher, doc])
    session.commit()
    doc_id = doc.id
    owner_id = owner.id
    publisher_id = publisher.id
    session.close()
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = [app_module.RoleEnum.PUBLISHER.value]
    resp = client.post(
        f"/api/documents/{doc_id}/publish", data={}, headers={"HX-Request": "true"}
    )
    assert resp.status_code == 204
    assert resp.headers["HX-Trigger"] == json.dumps({"showToast": "Document published"})
    assert len(q.jobs) == 1
    assert q.jobs[0].args[0] == owner_id


def test_publish_document_without_version_returns_400(monkeypatch):
    app_module, models, q = _setup_app(monkeypatch)
    session = models.SessionLocal()
    owner = models.User(username="owner")
    publisher = models.User(username="publisher")
    doc = models.Document(doc_key="", title="Doc1", status="Approved", owner=owner)
    session.add_all([owner, publisher, doc])
    session.commit()
    doc_id = doc.id
    publisher_id = publisher.id
    session.close()
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": publisher_id}
        sess["roles"] = [app_module.RoleEnum.PUBLISHER.value]
    resp = client.post(
        f"/api/documents/{doc_id}/publish", data={}, headers={"HX-Request": "true"}
    )
    assert resp.status_code == 400
    assert resp.json["error"] == "Document not reviewable or missing active version"
    assert len(q.jobs) == 0
