import io
import os
import importlib


# Provide required environment variables before importing the app
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
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
        "tags": "",
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

    def fake_create_document_api():
        captured.update(app_module.request.get_json() or {})
        return app_module.jsonify({"id": 1}), 201

    app_module.create_document_api = fake_create_document_api

    resp = client.post("/documents/new?step=3")
    assert resp.status_code == 302
    assert captured["department"] == step1_data["department"]
    assert captured["type"] == step1_data["type"]
