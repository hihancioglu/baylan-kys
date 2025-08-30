import os
import importlib

# Set required environment variables before importing the application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")


def test_onlyoffice_callback_allows_unauthenticated_post():
    os.environ.pop("PORTAL_PUBLIC_BASE_URL", None)

    app_module = importlib.reload(importlib.import_module("app"))
    models = importlib.reload(importlib.import_module("models"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()

    session = models.SessionLocal()
    doc = models.Document(doc_key="doc.docx", title="Doc")
    session.add(doc)
    session.commit()
    doc_id = doc.id
    doc_key = doc.doc_key
    session.close()

    resp = client.post(
        f"/onlyoffice/callback/{doc_key}",
        json={"status": 2, "url": "http://s3/doc.docx"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"error": 0}

    session = models.SessionLocal()
    updated = session.get(models.Document, doc_id)
    assert updated.minor_version == 1
    revisions = session.query(models.DocumentRevision).filter_by(doc_id=doc_id).all()
    assert len(revisions) == 1
    session.close()
