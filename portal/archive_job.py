"""Cron job to archive documents whose retention period has expired."""
from datetime import datetime, timedelta
from models import get_session, Document
from storage import move_to_archive


def run() -> None:
    session = get_session()
    now = datetime.utcnow()
    docs = (
        session.query(Document)
        .filter(Document.retention_period != None)
        .filter(Document.status != "Archived")
        .all()
    )
    for doc in docs:
        base = doc.created_at or now
        expire_at = base + timedelta(days=doc.retention_period)
        if expire_at <= now:
            move_to_archive(doc.doc_key, doc.retention_period or 0)
            doc.status = "Archived"
            doc.archived_at = now
    session.commit()
    session.close()


if __name__ == "__main__":
    run()
