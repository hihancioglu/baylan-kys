"""Send annual periodic review alerts for documents.

This module is expected to be invoked by an external cron scheduler once per year.
Example crontab entry:
0 0 1 1 * python -m portal.periodic_review
"""
from models import get_session, Document, User
from notifications import notify_revision_time


def send_periodic_review_alert(doc: Document) -> None:
    session = get_session()
    user_ids = [u.id for u in session.query(User).all()]
    session.close()
    notify_revision_time(doc, user_ids)


def run() -> None:
    session = get_session()
    docs = session.query(Document).filter(Document.status != "Archived").all()
    for doc in docs:
        send_periodic_review_alert(doc)
    session.close()


if __name__ == "__main__":
    run()
