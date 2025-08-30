import os
import importlib

# Set required environment variables before importing the application
os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")
os.environ.setdefault("S3_ENDPOINT", "http://s3")

def test_edit_route_builds_callback_url_from_request_host():
    """When PORTAL_PUBLIC_BASE_URL is unset, the host URL is used."""
    # Ensure the environment variable is not defined
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
    session.close()

    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = [models.RoleEnum.CONTRIBUTOR.value]

    resp = client.get(f"/documents/{doc_id}/edit")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert f"callbackUrl\": \"http://localhost/onlyoffice/callback/{doc.doc_key}\"" in body
    assert "value: 'Bearer ' + editorToken" in body
