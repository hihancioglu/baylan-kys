import importlib
import os
from unittest.mock import MagicMock

# Ensure S3 endpoint is set before importing app
os.environ.setdefault("S3_ENDPOINT", "http://s3")

def test_create_document_after_standard_map():
    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config.update(WTF_CSRF_ENABLED=False)
    client = app_module.app.test_client()

    # Authenticate as contributor
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "username": "tester"}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    # ensure storage head succeeds
    app_module.storage_client.head_object = MagicMock()

    # Call standard map helper before creating a document to exercise session cleanup
    app_module.get_standard_map()

    payload = {
        "code": "DOC-SESSION",
        "title": "Session Test",
        "type": "T",
        "department": "Dept",
        "tags": "tag1,tag2",
        "uploaded_file_key": "key",
        "uploaded_file_name": "file.txt",
        "standard": "ISO9001",
    }
    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 201
