import os
from pathlib import Path
import sys

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

_db_path = Path("test_search.db")
if _db_path.exists():
    _db_path.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"

# Make application modules importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))

import pytest
from portal.models import SessionLocal, Document, Base, engine
from portal.app import app, _get_documents

# Create database schema and populate sample data
Base.metadata.create_all(bind=engine)
session = SessionLocal()

session.add_all([
    Document(doc_key="doc1.docx", title="Safety Procedure", code="DOC-001", status="Published"),
    Document(doc_key="doc2.docx", title="Quality Manual", code="MAN-002", status="Published"),
    Document(doc_key="doc3.docx", title="Operations Guide", code="OPS-100", status="Published"),
])
session.commit()
session.close()


def test_get_documents_search_filters_by_q():
    """Documents can be filtered by title or code using the q parameter."""
    # Search by title, case-insensitive
    with app.test_request_context("/documents", query_string={"q": "manual"}):
        docs, _, _, filters, params = _get_documents()
    titles = {d.title for d in docs}
    assert titles == {"Quality Manual"}
    assert filters["q"] == "manual"
    assert params["q"] == "manual"

    # Search by code, case-insensitive
    with app.test_request_context("/documents", query_string={"q": "doc-001"}):
        docs, _, _, _, _ = _get_documents()
    codes = {d.code for d in docs}
    assert codes == {"DOC-001"}
