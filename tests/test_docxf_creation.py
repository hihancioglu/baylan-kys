import os
from pathlib import Path
import sys

# Set up environment variables before importing application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")

# Ensure modules can be imported
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))

import boto3
from botocore.stub import Stubber, ANY
import pytest
import importlib

portal_app = None
m = None
docxf_render_module = None
storage = None
docxf_render = None
Base = None
engine = None
SessionLocal = None
Document = None
app = None


@pytest.fixture(autouse=True)
def load_app_modules():
    global portal_app, m, docxf_render_module, storage, docxf_render
    global Base, engine, SessionLocal, Document, app
    m = importlib.reload(importlib.import_module("models"))
    portal_app = importlib.reload(importlib.import_module("app"))
    docxf_render_module = importlib.reload(importlib.import_module("docxf_render"))
    storage = importlib.import_module("portal.storage")
    docxf_render = importlib.import_module("portal.docxf_render")
    Base = m.Base
    engine = m.engine
    SessionLocal = m.SessionLocal
    Document = m.Document
    app = portal_app.app
    Base.metadata.create_all(bind=engine)
    app.config["WTF_CSRF_ENABLED"] = False


@pytest.fixture()
def client():
    return app.test_client()


def test_docxf_document_creation(client):
    # Prepare session with contributor role
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["contributor"]

    s3 = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    stubber = Stubber(s3)
    stubber.add_response(
        "put_object",
        {},
        {"Bucket": storage.S3_BUCKET, "Key": ANY, "Body": ANY},
    )
    stubber.add_response(
        "put_object",
        {},
        {"Bucket": storage.S3_BUCKET, "Key": ANY, "Body": ANY},
    )
    stubber.activate()

    storage._s3 = s3
    docxf_render._s3 = s3
    docxf_render_module._s3 = s3
    storage.S3_BUCKET = "test-bucket"
    docxf_render.S3_BUCKET = "test-bucket"
    docxf_render_module.S3_BUCKET = "test-bucket"
    storage.generate_presigned_url = (
        lambda key, expires_in=None: f"https://example.com/{key}"
    )
    portal_app.generate_presigned_url = storage.generate_presigned_url

    # Avoid external requests
    def fake_render_form(form_name, data=None, outputtype="pdf"):
        return b"dummy"

    docxf_render.render_form = fake_render_form
    docxf_render_module.render_form = fake_render_form

    payload = {"title": "Test Doc", "code": "T-001"}
    resp = client.post(
        "/api/documents/from-docxf",
        json={"form_id": "my-form", "payload": payload},
    )
    assert resp.status_code == 201
    data = resp.get_json()

    # JSON validations
    assert data.get("version") == "1.0"
    assert data.get("preview_url")

    # Ensure S3 interactions occurred
    stubber.assert_no_pending_responses()

    # Verify version in database
    session_db = SessionLocal()
    doc = session_db.query(Document).get(data["id"])
    assert f"{doc.major_version}.{doc.minor_version}" == "1.0"
    session_db.close()
