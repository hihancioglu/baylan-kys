import io
import os
import sys
import importlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ.setdefault("S3_BUCKET_MAIN", "test-bucket")
os.environ.setdefault("S3_ACCESS_KEY", "test")
os.environ.setdefault("S3_SECRET_KEY", "test")
os.environ.setdefault(
    "ISO_STANDARDS",
    "ISO9001:ISO 9001,ISO27001:ISO 27001,ISO14001:ISO 14001",
)

ISO_MAP = dict(item.split(":", 1) for item in os.environ["ISO_STANDARDS"].split(","))
FIRST_STANDARD = list(ISO_MAP.keys())[0]
FIRST_LABEL = ISO_MAP[FIRST_STANDARD]

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models():
    app_module = importlib.import_module("app")
    models_module = importlib.import_module("models")
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    return app_module, models_module


@pytest.fixture()
def client(app_models):
    app_module, _ = app_models
    client = app_module.app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = ["contributor", "reader"]
    return client


def _mock_env(app_module):
    storage = importlib.import_module("storage")
    storage.storage_client.head_object = MagicMock(return_value={})
    storage.storage_client.put_object = MagicMock(return_value={})
    app_module.extract_text = lambda key: "dummy"
    app_module.notify_mandatory_read = lambda doc, users: None
    return storage


def test_document_standard_creation_flow(app_models, client):
    app_module, models = app_models
    storage = _mock_env(app_module)

    step1_data = {
        "code": "FLOW1",
        "title": "Flow Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "standard": FIRST_STANDARD,
    }
    resp = client.post("/documents/new?step=1", data=step1_data)
    assert resp.status_code == 302

    upload_file = (io.BytesIO(b"hello"), "file.txt")
    resp = client.post(
        "/documents/new?step=2",
        data={"upload_file": upload_file},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    assert storage.storage_client.put_object.called

    resp = client.post("/documents/new?step=3", data={})
    assert resp.status_code == 302

    resp = client.get(f"/documents?standard={FIRST_STANDARD}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Flow Doc" in body
    assert f"<th colspan=\"7\">{FIRST_LABEL}</th>" in body
