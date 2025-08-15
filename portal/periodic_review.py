"""Send annual periodic review alerts for documents.

This module is expected to be invoked by an external cron scheduler once per year.
Example crontab entry:
0 0 1 1 * python -m portal.periodic_review
"""
from models import get_session, Document


def send_periodic_review_alert(doc: Document) -> None:
    """Placeholder alert implementation."""
    print(f"Periodic review alert for document {doc.id}")


def run() -> None:
    session = get_session()
    docs = session.query(Document).filter(Document.status != "Archived").all()
    for doc in docs:
        send_periodic_review_alert(doc)
    session.close()


if __name__ == "__main__":
    run()
