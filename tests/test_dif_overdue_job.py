import importlib
from datetime import datetime, timedelta
from sqlalchemy.orm import sessionmaker

def test_dif_overdue_job_notifies_and_marks(monkeypatch):
    rq = importlib.import_module("rq")
    notifications = importlib.reload(importlib.import_module("notifications"))
    q = rq.Queue("notifications")
    monkeypatch.setattr(notifications, "queue", q)
    job_module = importlib.reload(importlib.import_module("dif_overdue_job"))
    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    session = Session()
    role = models.Role(name="reviewer")
    user = models.User(username="rev", email="rev@example.com", roles=[role])
    requester = models.User(username="req")
    session.add_all([role, user, requester])
    session.commit()
    dif = models.DifRequest(subject="S", requester_id=requester.id)
    session.add(dif)
    session.commit()
    step = models.DifWorkflowStep(
        dif_id=dif.id,
        role="reviewer",
        step_order=1,
        sla_hours=1,
        status="Pending",
        created_at=datetime.utcnow() - timedelta(hours=2),
    )
    session.add(step)
    session.commit()
    step_id = step.id
    session.close()
    job_module.run()
    session = Session()
    step_db = session.get(models.DifWorkflowStep, step_id)
    assert step_db.status == "Overdue"
    session.close()
    assert len(q.jobs) == 1
