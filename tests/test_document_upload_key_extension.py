import os
from pathlib import Path
import sys
import importlib
from unittest.mock import MagicMock

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET_MAIN", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")
os.environ.setdefault("DATABASE_URL", "sqlite://")

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


def test_api_appends_extension_to_key():
    portal_app = importlib.reload(importlib.import_module("app"))
    models = importlib.reload(importlib.import_module("models"))
    storage = importlib.import_module("storage")
    models.Base.metadata.drop_all(bind=models.engine)
    models.Base.metadata.create_all(bind=models.engine)
    models.SessionLocal.configure(expire_on_commit=False)
    portal_app.app.config["WTF_CSRF_ENABLED"] = False
    client = portal_app.app.test_client()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["contributor"]

    storage.storage_client.head_object = MagicMock(return_value={})

    portal_app.extract_text = lambda key: "dummy"
    portal_app.notify_mandatory_read = lambda doc, users: None

    first_standard = next(iter(portal_app.STANDARD_MAP.keys()))
    payload = {
        "code": "DOC1",
        "title": "My Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "uploaded_file_key": "abc123",
        "uploaded_file_name": "file.txt",
        "standard": first_standard,
    }

    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["doc_key"] == "abc123.txt"

    session_db = models.SessionLocal()
    doc = session_db.query(models.Document).get(data["id"])
    assert doc.doc_key == "abc123.txt"
    session_db.close()

    storage.storage_client.head_object.assert_called_once_with(Key="abc123.txt")
