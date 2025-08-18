"""Cron job to archive documents whose retention period has expired."""
from datetime import datetime, timedelta
from models import get_session, Document, User
from storage import storage_client
from app import log_action


def run() -> None:
    session = get_session()
    now = datetime.utcnow()
    docs = (
        session.query(Document)
        .filter(Document.retention_period != None)
        .filter(Document.status != "Archived")
        .all()
    )
    # pick the first user as the acting user for audit logging
    system_user = session.query(User.id).order_by(User.id).first()
    system_user_id = system_user[0] if system_user else 0
    for doc in docs:
        base = doc.created_at or now
        expire_at = base + timedelta(days=doc.retention_period)
        if expire_at <= now:
            storage_client.move_to_archive(doc.doc_key, doc.retention_period or 0)
            doc.status = "Archived"
            doc.archived_at = now
            log_action(system_user_id, doc.id, "archive_document")
    session.commit()
    session.close()


if __name__ == "__main__":
    run()
