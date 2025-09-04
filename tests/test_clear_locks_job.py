import importlib
from datetime import datetime, timedelta
from sqlalchemy.orm import sessionmaker


def test_clear_locks_job_clears_expired_locks():
    job = importlib.import_module("clear_locks_job")
    models = importlib.import_module("models")
    Session = sessionmaker(bind=models.engine)
    session = Session()
    doc = models.Document(
        file_key="orig.pdf",
        title="Doc",
        status="Published",
        mime="application/pdf",
        locked_by=1,
        lock_expires_at=datetime.utcnow() - timedelta(minutes=1),
    )
    session.add(doc)
    session.commit()
    doc_id = doc.id
    session.close()
    job.run()
    session = Session()
    doc_db = session.get(models.Document, doc_id)
    assert doc_db.locked_by is None
    assert doc_db.lock_expires_at is None
    session.close()
