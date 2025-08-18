import os
import importlib
from unittest.mock import MagicMock

# Set required environment variables before importing the app
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

def test_mandatory_read_notification_does_not_detach():
    app_module = importlib.reload(importlib.import_module("app"))
    notifications = importlib.reload(importlib.import_module("notifications"))
    storage = importlib.import_module("storage")

    # Avoid external calls
    storage.storage_client.head_object = MagicMock(return_value={})
    app_module.extract_text = lambda key: "dummy"
    app_module.index_document = lambda doc, content: None
    notifications.notify_user = MagicMock()

    app_module.app.config["WTF_CSRF_ENABLED"] = False
    client = app_module.app.test_client()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    payload = {
        "code": "DOC1",
        "title": "My Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "uploaded_file_key": "abc123",
        "uploaded_file_name": "file.txt",
    }

    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 201
