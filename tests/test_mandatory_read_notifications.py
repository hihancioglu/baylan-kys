import os
import importlib
import sys
from unittest.mock import MagicMock

# Set required environment variables before importing the app
os.environ.setdefault("S3_ENDPOINT", "http://s3")

def test_mandatory_read_notification_does_not_detach():
    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
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

    first_standard = next(iter(app_module.STANDARD_MAP.keys()))
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
