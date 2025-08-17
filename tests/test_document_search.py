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
from sqlalchemy import or_
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


@pytest.fixture(autouse=True)
def patch_search(monkeypatch):
    """Provide a stand-in search backend for tests."""

    def fake_search(keyword, filters, page=1, per_page=10):
        s = SessionLocal()
        query = s.query(Document)
        if keyword:
            like = f"%{keyword}%"
            query = query.filter(
                or_(Document.title.ilike(like), Document.code.ilike(like))
            )
        if filters.get("status"):
            query = query.filter(Document.status == filters["status"])
        total = query.count()
        docs = (
            query.order_by(Document.id)
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        s.close()
        facets = {"status": {filters.get("status", "Published"): total}}
        return [{"id": d.id} for d in docs], facets, total

    monkeypatch.setattr("portal.app.search_documents", fake_search)


def test_get_documents_search_filters_by_q():
    """Documents can be filtered by title or code using the q parameter."""

    with app.test_request_context("/documents", query_string={"q": "manual"}):
        docs, _, _, filters, params, facets = _get_documents()
    titles = {d.title for d in docs}
    assert titles == {"Quality Manual"}
    assert filters["q"] == "manual"
    assert params["q"] == "manual"
    assert facets["status"]["Published"] == 1

    with app.test_request_context("/documents", query_string={"q": "doc-001"}):
        docs, _, _, _, _, _ = _get_documents()
    codes = {d.code for d in docs}
    assert codes == {"DOC-001"}


def test_get_documents_search_pagination():
    """Search results are paginated according to page and page_size."""

    with app.test_request_context(
        "/documents", query_string={"status": "Published", "page": 2, "page_size": 1}
    ):
        docs, page, pages, filters, params, facets = _get_documents()

    assert len(docs) == 1
    assert page == 2
    assert pages == facets["status"]["Published"]
    assert facets["status"]["Published"] >= 3

