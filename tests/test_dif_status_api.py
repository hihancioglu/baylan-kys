import os
import importlib
from sqlalchemy.orm import sessionmaker


def test_dif_approve_notifies_requester_and_next(monkeypatch):
    os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
    os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
    os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
    os.environ.setdefault("S3_ENDPOINT", "http://s3")

    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()

    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    session = Session()

    approver_role = models.Role(name="approver")
    reviewer_role = models.Role(name="reviewer")
    session.add_all([approver_role, reviewer_role])
    session.commit()

    requester = models.User(username="req")
    approver = models.User(username="appr", roles=[approver_role])
    reviewer = models.User(username="rev", roles=[reviewer_role])
    session.add_all([requester, approver, reviewer])
    session.commit()

    dif = models.DifRequest(subject="Sub", requester_id=requester.id)
    session.add(dif)
    session.commit()

    step1 = models.DifWorkflowStep(dif_id=dif.id, role="approver", step_order=1, status="Pending")
    step2 = models.DifWorkflowStep(dif_id=dif.id, role="reviewer", step_order=2, status="Pending")
    session.add_all([step1, step2])
    session.commit()

    requester_id = requester.id
    approver_id = approver.id
    reviewer_id = reviewer.id
    dif_id = dif.id
    session.close()

    calls = []

    def fake_notify(uid, subject, body):
        calls.append(uid)

    monkeypatch.setattr(app_module, "notify_user", fake_notify)

    with client.session_transaction() as sess:
        sess["user"] = {"id": approver_id}
        sess["roles"] = [app_module.RoleEnum.APPROVER.value]

    resp = client.post(f"/api/dif/{dif_id}/approve")
    assert resp.status_code == 200

    session = Session()
    dif_obj = session.get(models.DifRequest, dif_id)
    assert dif_obj.status == "in_review"
    logs = session.query(models.AuditLog).filter_by(entity_type="DifRequest", entity_id=dif_id, action="approved").all()
    assert len(logs) == 1
    session.close()

    assert set(calls) == {requester_id, reviewer_id}
