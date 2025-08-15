from models import get_session, Document, DocumentRevision


def restore_version(doc_id: int, version: str) -> Document:
    """Restore a document to a previous major.minor version."""
    major, minor = (int(x) for x in version.split("."))
    session = get_session()
    rev = (
        session.query(DocumentRevision)
        .filter_by(doc_id=doc_id, major_version=major, minor_version=minor)
        .order_by(DocumentRevision.created_at.desc())
        .first()
    )
    if not rev:
        session.close()
        raise ValueError("Revision not found")
    doc = session.get(Document, doc_id)
    if not doc:
        session.close()
        raise ValueError("Document not found")
    doc.major_version = major
    doc.minor_version = minor
    doc.revision_notes = rev.revision_notes
    session.commit()
    session.refresh(doc)
    session.close()
    return doc
