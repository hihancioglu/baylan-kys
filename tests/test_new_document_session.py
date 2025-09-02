import io
import os
import importlib
from unittest.mock import MagicMock


# Provide required environment variables before importing the app
os.environ.setdefault("S3_ENDPOINT", "http://s3")


def test_upload_does_not_bloat_cookie():
    """Uploading a file stores data server-side and keeps cookies small."""
    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config.update(WTF_CSRF_ENABLED=False)
    client = app_module.app.test_client()

    # Grant contributor role for access to the route
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "username": "tester"}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    step1_data = {
        "code": "DOC-1",
        "title": "My Doc",
        "type": "T",
        "department": "Dept",
        "standard": "ISO9001",
        "tags": "tag",
    }
    resp = client.post("/documents/new?step=1", data=step1_data)
    assert resp.status_code == 302

    big_file = (io.BytesIO(b"a" * 5000), "big.txt")
    resp = client.post(
        "/documents/new?step=2",
        data={"upload_file": big_file},
        content_type="multipart/form-data",
    )

    cookie = resp.headers.get("Set-Cookie", "")
    assert len(cookie) < 4093


def test_final_payload_includes_department_and_type():
    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config.update(WTF_CSRF_ENABLED=False)
    client = app_module.app.test_client()
    app_module.storage_client.put_object = MagicMock()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "username": "tester"}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    step1_data = {
        "code": "DOC-2",
        "title": "Other Doc",
        "type": "Process",
        "department": "QA",
        "standard": "ISO9001",
        "tags": "",
    }
    resp = client.post("/documents/new?step=1", data=step1_data)
    assert resp.status_code == 302

    file = (io.BytesIO(b"content"), "file.txt")
    resp = client.post(
        "/documents/new?step=2",
        data={"upload_file": file},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302

    captured = {}

    def fake_create_document_api(data=None):
        captured.update(data or {})
        return app_module.jsonify({"id": 1}), 201

    app_module.create_document_api = fake_create_document_api

    resp = client.post("/documents/new?step=3")
    assert resp.status_code == 302
    assert captured["department"] == step1_data["department"]
    assert captured["type"] == step1_data["type"]


def test_cancel_cleans_up_upload():
    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config.update(WTF_CSRF_ENABLED=False)
    client = app_module.app.test_client()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "username": "tester"}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]

    step1_data = {
        "code": "DOC-3",
        "title": "Cancel Doc",
        "type": "T",
        "department": "Dept",
        "standard": "ISO9001",
        "tags": "",
    }
    resp = client.post("/documents/new?step=1", data=step1_data)
    assert resp.status_code == 302

    file = (io.BytesIO(b"content"), "file.txt")
    app_module.storage_client.put_object = MagicMock()
    app_module.storage_client.delete_object = MagicMock()
    resp = client.post(
        "/documents/new?step=2",
        data={"upload_file": file},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302

    with client.session_transaction() as sess:
        key = sess.get("uploaded_file_key")
        assert key

    resp = client.post("/documents/new?step=3", data={"cancel": "1"})
    assert resp.status_code == 302
    app_module.storage_client.delete_object.assert_called_once_with(Key=key)
    with client.session_transaction() as sess:
        assert "uploaded_file_key" not in sess


def test_session_reset_after_user_id_error():
    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config.update(WTF_CSRF_ENABLED=False, AUTO_REVIEW_ON_UPLOAD=False)
    client = app_module.app.test_client()
    app_module.storage_client.head_object = MagicMock()
    app_module.enqueue_preview = lambda *args, **kwargs: None
    app_module.extract_text = lambda key: ""
    app_module.index_document = lambda doc, content: None
    app_module.notify_mandatory_read = lambda doc, user_ids: None
    app_module.services.submit_for_approval = lambda *args, **kwargs: None

    payload = {
        "code": "DOC-4",
        "title": "Doc",
        "type": "T",
        "department": "Dept",
        "tags": "tag",
        "uploaded_file_key": "k1",
        "standard": "ISO9001",
    }

    with client.session_transaction() as sess:
        sess["user"] = {"username": "tester"}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]
    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 400

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "username": "tester"}
        sess["roles"] = [app_module.RoleEnum.CONTRIBUTOR.value]
    resp = client.post("/api/documents", json=payload)
    assert resp.status_code == 201
