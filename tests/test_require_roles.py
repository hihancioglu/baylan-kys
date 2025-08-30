import os
import importlib
import pytest

# Set minimal environment variables before importing the application
os.environ.setdefault("S3_ENDPOINT", "http://s3")


@pytest.fixture()
def client_and_models():
    app_module = importlib.reload(importlib.import_module("app"))
    models = importlib.reload(importlib.import_module("models"))
    from auth import require_roles

    app_module.app.config["WTF_CSRF_ENABLED"] = False

    @app_module.app.route("/qa")
    @require_roles(models.RoleEnum.QUALITY_ADMIN.value)
    def qa_route():
        return "ok"

    @app_module.app.route("/qa-approve")
    @require_roles(models.RoleEnum.QUALITY_ADMIN.value, models.RoleEnum.APPROVER.value)
    def qa_approve_route():
        return "ok"

    client = app_module.app.test_client()
    return client, models


def test_require_roles_single_role(client_and_models):
    client, models = client_and_models
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = []
    assert client.get("/qa").status_code == 403

    with client.session_transaction() as sess:
        sess["roles"] = [models.RoleEnum.QUALITY_ADMIN.value]
    assert client.get("/qa").status_code == 200


def test_require_roles_multiple_roles(client_and_models):
    client, models = client_and_models
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = [models.RoleEnum.QUALITY_ADMIN.value]
    assert client.get("/qa-approve").status_code == 403

    with client.session_transaction() as sess:
        sess["roles"] = [
            models.RoleEnum.QUALITY_ADMIN.value,
            models.RoleEnum.APPROVER.value,
        ]
    assert client.get("/qa-approve").status_code == 200

