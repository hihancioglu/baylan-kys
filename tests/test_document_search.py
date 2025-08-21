import os
from pathlib import Path
import sys

# Ensure environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

import pytest
from sqlalchemy import or_
import importlib
from flask import session as flask_session

SessionLocal = None
Document = None
Role = None
app = None
_get_documents = None


@pytest.fixture(autouse=True)
def app_models():
    global SessionLocal, Document, Role, app, _get_documents
    m = importlib.reload(importlib.import_module("models"))
    a = importlib.reload(importlib.import_module("app"))
    m.Base.metadata.create_all(bind=m.engine)
    SessionLocal = m.SessionLocal
    Document = m.Document
    Role = m.Role
    app = a.app
    _get_documents = a._get_documents
    db = SessionLocal()
    db.query(Role).delete()
    db.add(Role(name="reader", standard_scope="ALL"))
    db.commit()
    db.close()
    return m

def _populate_docs():
    session = SessionLocal()
    session.query(Document).delete()
    session.add_all([
        Document(
            doc_key="doc1.docx",
            title="Safety Procedure",
            code="DOC-001",
            standard_code="ISO9001",
            status="Published",
        ),
        Document(
            doc_key="doc2.docx",
            title="Quality Manual",
            code="MAN-002",
            standard_code="ISO14001",
            status="Published",
        ),
        Document(
            doc_key="doc3.docx",
            title="Operations Guide",
            code="OPS-100",
            status="Published",
        ),
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
        if filters.get("standard"):
            query = query.filter(Document.standard_code == filters["standard"])
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

    import app as a
    monkeypatch.setattr(a, "search_documents", fake_search)


def test_get_documents_search_filters_by_q():
    """Documents can be filtered by title or code using the q parameter."""
    _populate_docs()
    with app.test_request_context("/documents", query_string={"q": "manual"}):
        flask_session["roles"] = ["reader"]
        docs, _, _, filters, params, facets = _get_documents()
    titles = {d.title for d in docs}
    assert titles == {"Quality Manual"}
    assert filters["q"] == "manual"
    assert params["q"] == "manual"
    assert facets["status"]["Published"] == 1

    with app.test_request_context("/documents", query_string={"q": "doc-001"}):
        flask_session["roles"] = ["reader"]
        docs, _, _, _, _, _ = _get_documents()
    codes = {d.code for d in docs}
    assert codes == {"DOC-001"}


def test_get_documents_search_pagination():
    """Search results are paginated according to page and page_size."""
    _populate_docs()
    with app.test_request_context(
        "/documents", query_string={"status": "Published", "page": 2, "page_size": 1}
    ):
        flask_session["roles"] = ["reader"]
        docs, page, pages, filters, params, facets = _get_documents()

    assert len(docs) == 1
    assert page == 2
    assert pages == facets["status"]["Published"]
    assert facets["status"]["Published"] >= 3


def test_get_documents_filter_by_standard():
    """Documents can be filtered by standard code."""
    _populate_docs()
    with app.test_request_context("/documents", query_string={"standard": "ISO9001"}):
        flask_session["roles"] = ["reader"]
        docs, _, _, filters, params, _ = _get_documents()

    titles = {d.title for d in docs}
    assert titles == {"Safety Procedure"}
    assert filters["standard"] == "ISO9001"
    assert params["standard"] == "ISO9001"


def test_get_documents_normalizes_missing_standard_code():
    """Documents with no standard_code are normalized for grouping."""
    _populate_docs()
    with app.test_request_context("/documents"):
        flask_session["roles"] = ["reader"]
        docs, _, _, _, _, _ = _get_documents()

    codes = {d.standard_code for d in docs}
    assert None not in codes
    assert "" in codes


def test_get_documents_filters_by_role_scope():
    """Users only see documents within their role's standard scope."""
    _populate_docs()
    db = SessionLocal()
    db.add(Role(name="auditor", standard_scope="ISO9001"))
    db.commit()
    db.close()
    with app.test_request_context("/documents"):
        flask_session["roles"] = ["auditor"]
        docs, _, _, _, _, _ = _get_documents()

    titles = {d.title for d in docs}
    assert titles == {"Safety Procedure"}

