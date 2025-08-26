"""Cron job to notify overdue DIF workflow steps."""
from datetime import datetime, timedelta
from models import get_session, DifWorkflowStep, User, Role
from notifications import notify_dif_step_overdue


def run() -> None:
    """Scan for workflow steps exceeding their SLA and notify responsible users."""
    session = get_session()
    now = datetime.utcnow()
    steps = (
        session.query(DifWorkflowStep)
        .filter(DifWorkflowStep.status == "Pending")
        .filter(DifWorkflowStep.sla_hours != None)
        .all()
    )
    for step in steps:
        base = step.created_at or getattr(step.dif_request, "created_at", None)
        if not base:
            continue
        if now - base > timedelta(hours=step.sla_hours or 0):
            users = (
                session.query(User.id)
                .join(User.roles)
                .filter(Role.name == step.role)
                .all()
            )
            user_ids = [u.id for u in users]
            notify_dif_step_overdue(step, user_ids)
            step.status = "Overdue"
    session.commit()
    session.close()


if __name__ == "__main__":
    run()
