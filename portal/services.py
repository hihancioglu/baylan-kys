from models import get_session, Document, DocumentRevision, WorkflowStep


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


def submit_for_approval(doc_id: int) -> Document:
    """Move a document to review state and create workflow steps."""
    session = get_session()
    doc = session.get(Document, doc_id)
    if not doc:
        session.close()
        raise ValueError("Document not found")
    doc.status = "Review"
    steps = [
        WorkflowStep(doc_id=doc_id, step_order=i, approver=approver)
        for i, approver in enumerate(["manager", "quality"], start=1)
    ]
    session.add_all(steps)
    session.commit()
    session.refresh(doc)
    session.close()
    return doc
