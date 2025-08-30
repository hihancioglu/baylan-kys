import os
import io
import importlib
import sys
from datetime import datetime, timedelta
from sqlalchemy.orm import sessionmaker


def test_creation_validation_and_attachment_upload(monkeypatch):
    os.environ.setdefault("S3_ENDPOINT", "http://s3")

    storage = importlib.import_module("storage")
    monkeypatch.setattr(storage.storage_client, "put", lambda **_: None)

    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()

    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    db = Session()
    role = models.Role(name="contributor")
    user = models.User(username="creator", roles=[role])
    db.add_all([role, user])
    db.commit()
    uid = user.id
    db.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": uid}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    resp = client.post("/dif/new", data={})
    assert resp.status_code == 400
    assert b"Subject is required" in resp.data

    data = {
        "subject": "Test",
        "description": "desc",
        "impact": "high",
        "attachment": (io.BytesIO(b"data"), "file.txt"),
    }
    resp = client.post(
        "/dif/new", data=data, content_type="multipart/form-data"
    )
    assert resp.status_code == 302

    db = Session()
    dif = db.query(models.DifRequest).first()
    assert dif.attachment_key
    db.close()


def test_listing_filters(monkeypatch):
    os.environ.setdefault("S3_ENDPOINT", "http://s3")

    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()

    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    db = Session()
    reader_role = models.Role(name="reader")
    viewer = models.User(username="viewer", roles=[reader_role])
    u1 = models.User(username="u1")
    u2 = models.User(username="u2")
    db.add_all([reader_role, viewer, u1, u2])
    db.commit()
    dif_new = models.DifRequest(
        subject="New", requester_id=u1.id, status="approved"
    )
    dif_old = models.DifRequest(
        subject="Old",
        requester_id=u2.id,
        status="rejected",
        created_at=datetime.utcnow() - timedelta(days=5),
    )
    db.add_all([dif_new, dif_old])
    db.commit()
    viewer_id = viewer.id
    db.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": viewer_id}
        sess["roles"] = [app_module.RoleEnum.READER.value]

    resp = client.get("/dif?status=approved")
    assert b"New" in resp.data and b"Old" not in resp.data

    start = (datetime.utcnow() - timedelta(days=2)).strftime("%Y-%m-%d")
    resp = client.get(f"/dif?start={start}")
    assert b"New" in resp.data and b"Old" not in resp.data



def test_workflow_actions_and_notifications(monkeypatch):
    os.environ.setdefault("S3_ENDPOINT", "http://s3")

    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()

    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    db = Session()
    approver_role = models.Role(name="approver")
    reviewer_role = models.Role(name="reviewer")
    db.add_all([approver_role, reviewer_role])
    db.commit()
    requester = models.User(username="req")
    approver = models.User(username="appr", roles=[approver_role])
    reviewer = models.User(username="rev", roles=[reviewer_role])
    db.add_all([requester, approver, reviewer])
    db.commit()
    requester_id, approver_id, reviewer_id = requester.id, approver.id, reviewer.id

    def make_dif():
        dif = models.DifRequest(subject="S", requester_id=requester_id)
        db.add(dif)
        db.commit()
        step1 = models.DifWorkflowStep(
            dif_id=dif.id, role="approver", step_order=1, status="Pending"
        )
        step2 = models.DifWorkflowStep(
            dif_id=dif.id, role="reviewer", step_order=2, status="Pending"
        )
        db.add_all([step1, step2])
        db.commit()
        return dif.id

    approve_id = make_dif()
    reject_id = make_dif()
    changes_id = make_dif()
    db.close()

    calls = []

    def fake_notify(uid, subject, body):
        calls.append((uid, subject))

    monkeypatch.setattr(app_module, "notify_user", fake_notify)

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = [app_module.RoleEnum.APPROVER.value]
    start = len(calls)
    resp = client.post(f"/api/dif/{approve_id}/approve")
    assert resp.status_code == 200
    db = Session()
    step = db.query(models.DifWorkflowStep).filter_by(dif_id=approve_id, step_order=1).one()
    dif = db.get(models.DifRequest, approve_id)
    db.close()
    assert step.status == "Approved" and dif.status == "in_review"
    assert calls[start:] == [
        (requester_id, f"DIF Request #{approve_id} approved"),
        (reviewer_id, f"DIF Request #{approve_id} awaiting your review"),
    ]

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = [app_module.RoleEnum.APPROVER.value]
    start = len(calls)
    resp = client.post(f"/api/dif/{reject_id}/reject")
    assert resp.status_code == 200
    db = Session()
    step = db.query(models.DifWorkflowStep).filter_by(dif_id=reject_id, step_order=1).one()
    dif = db.get(models.DifRequest, reject_id)
    db.close()
    assert step.status == "Rejected" and dif.status == "rejected"
    assert calls[start:] == [
        (requester_id, f"DIF Request #{reject_id} rejected"),
        (reviewer_id, f"DIF Request #{reject_id} awaiting your review"),
    ]

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = [app_module.RoleEnum.APPROVER.value]
    start = len(calls)
    resp = client.post(f"/api/dif/{changes_id}/request-changes")
    assert resp.status_code == 200
    db = Session()
    step = db.query(models.DifWorkflowStep).filter_by(dif_id=changes_id, step_order=1).one()
    dif = db.get(models.DifRequest, changes_id)
    db.close()
    assert step.status == "Changes Requested" and dif.status == "in_review"
    assert calls[start:] == [
        (requester_id, f"Changes requested for DIF #{changes_id}"),
        (reviewer_id, f"DIF Request #{changes_id} awaiting your review"),
    ]


def test_sla_escalation(monkeypatch):
    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
    notifications = importlib.reload(importlib.import_module("notifications"))
    calls = []

    def fake_notify(step, user_ids):
        calls.append((step.id, tuple(user_ids)))

    monkeypatch.setattr(notifications, "notify_dif_step_overdue", fake_notify)
    job_module = importlib.reload(importlib.import_module("dif_overdue_job"))

    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    db = Session()
    role = models.Role(name="reviewer")
    user = models.User(username="rev", roles=[role])
    requester = models.User(username="req")
    db.add_all([role, user, requester])
    db.commit()
    dif = models.DifRequest(subject="S", requester_id=requester.id)
    db.add(dif)
    db.commit()
    step = models.DifWorkflowStep(
        dif_id=dif.id,
        role="reviewer",
        step_order=1,
        sla_hours=1,
        status="Pending",
        created_at=datetime.utcnow() - timedelta(hours=2),
    )
    db.add(step)
    db.commit()
    step_id, user_id = step.id, user.id
    db.close()

    job_module.run()

    db = Session()
    step_db = db.get(models.DifWorkflowStep, step_id)
    db.close()
    assert step_db.status == "Overdue"
    assert calls == [(step_id, (user_id,))]
