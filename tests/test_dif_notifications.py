import os
import importlib
import sys
from sqlalchemy.orm import sessionmaker


def test_dif_creation_enqueues_email(monkeypatch):
    # Set required environment variables before importing the app
    os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
    os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
    os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
    os.environ.setdefault("S3_ENDPOINT", "http://s3")

    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
    notifications = importlib.reload(importlib.import_module("notifications"))
    q = rq.Queue("notifications")
    monkeypatch.setattr(notifications, "queue", q)

    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()

    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    sess = Session()
    sess.add(models.User(id=1, username="u1", email="user@example.com"))
    sess.commit()
    sess.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    payload = {
        "subject": "My request",
        "description": "desc",
        "impact": "high",
    }
    resp = client.post("/dif/new", data=payload)
    assert resp.status_code == 302
    assert len(q.jobs) == 1
