import io
import importlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock
from datetime import datetime, timedelta

import pytest

os.environ.setdefault("S3_ENDPOINT", "http://s3")
os.environ["S3_BUCKET_MAIN"] = "local"

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))


@pytest.fixture()
def app_models():
    os.environ["S3_BUCKET_MAIN"] = "local"
    importlib.reload(importlib.import_module("storage"))
    importlib.reload(importlib.import_module("portal.storage"))
    models_module = importlib.reload(importlib.import_module("models"))
    app_module = importlib.reload(importlib.import_module("app"))
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    app_module.notify_user = lambda *a, **k: None
    return app_module, models_module


@pytest.fixture()
def client(app_models):
    app_module, _ = app_models
    return app_module.app.test_client()


def _login(client, user_id, roles=None):
    with client.session_transaction() as sess:
        sess["user"] = {"id": user_id, "name": f"User{user_id}"}
        sess["roles"] = roles or ["contributor"]


def _create_doc_and_users(models, u1_perms=None, u2_perms=None):
    u1_perms = u1_perms or {}
    u2_perms = u2_perms or {}
    session = models.SessionLocal()
    role1 = models.Role(name="r1")
    role2 = models.Role(name="r2")
    u1 = models.User(username="u1")
    u2 = models.User(username="u2")
    u1.roles.append(role1)
    u2.roles.append(role2)
    doc = models.Document(
        file_key="orig.pdf",
        title="Doc",
        status="Published",
        mime="application/pdf",
    )
    session.add_all([role1, role2, u1, u2, doc])
    session.commit()
    perm1 = models.DocumentPermission(
        role_id=role1.id,
        doc_id=doc.id,
        can_upload_version=u1_perms.get("upload", True),
        can_checkout=u1_perms.get("checkout", True),
        can_checkin=u1_perms.get("checkin", True),
        can_override=u1_perms.get("override", False),
    )
    perm2 = models.DocumentPermission(
        role_id=role2.id,
        doc_id=doc.id,
        can_upload_version=u2_perms.get("upload", True),
        can_checkout=u2_perms.get("checkout", True),
        can_checkin=u2_perms.get("checkin", True),
        can_override=u2_perms.get("override", False),
    )
    session.add_all([perm1, perm2])
    session.commit()
    doc_id = doc.id
    u1_id, u2_id = u1.id, u2.id
    session.close()
    return doc_id, u1_id, u2_id


def test_concurrent_upload_blocked_and_expiry(client, app_models):
    app_module, models = app_models
    storage = importlib.import_module("storage")
    storage.storage_client.put = MagicMock()
    doc_id, user1, user2 = _create_doc_and_users(models)

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=1)
    session.commit()
    session.close()

    _login(client, user2)
    data = {"file": (io.BytesIO(b"data"), "test.pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 409

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.lock_expires_at = datetime.utcnow() - timedelta(minutes=1)
    session.commit()
    session.close()

    services = importlib.import_module("services")
    services.clear_expired_locks()

    _login(client, user2)
    data = {"file": (io.BytesIO(b"data2"), "test.pdf")}
    resp = client.post(
        f"/api/documents/{doc_id}/versions",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201


def test_checkout_requires_permission(client, app_models):
    app_module, models = app_models
    doc_id, user1, _ = _create_doc_and_users(models, u1_perms={"checkout": False})
    _login(client, user1)
    resp = client.post(f"/api/documents/{doc_id}/checkout")
    assert resp.status_code == 403


def test_checkout_respects_lock_duration(client, app_models, monkeypatch):
    app_module, models = app_models
    doc_id, user1, _ = _create_doc_and_users(models)
    _login(client, user1)
    monkeypatch.setattr(app_module, "LOCK_DURATION_MINUTES", 5)
    monkeypatch.setitem(app_module.app.config, "LOCK_DURATION_MINUTES", 5)
    before = datetime.utcnow()
    resp = client.post(f"/api/documents/{doc_id}/checkout")
    assert resp.status_code == 200
    data = resp.get_json()
    locked_until = datetime.fromisoformat(data["locked_until"])
    assert abs((locked_until - before) - timedelta(minutes=5)) < timedelta(seconds=5)
    assert data["lock_expires_at"] == data["locked_until"]


def test_checkin_requires_permission(client, app_models):
    app_module, models = app_models
    doc_id, user1, _ = _create_doc_and_users(models, u1_perms={"checkout": True, "checkin": False})
    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=5)
    session.commit()
    session.close()
    _login(client, user1)
    resp = client.post(f"/api/documents/{doc_id}/checkin")
    assert resp.status_code == 403


def test_checkin_succeeds_with_permission(client, app_models):
    app_module, models = app_models
    doc_id, user1, _ = _create_doc_and_users(models, u1_perms={"checkout": True, "checkin": True})
    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=5)
    session.commit()
    session.close()
    _login(client, user1)
    resp = client.post(f"/api/documents/{doc_id}/checkin")
    assert resp.status_code == 200


def test_force_checkin_forbidden_without_override(client, app_models):
    app_module, models = app_models
    doc_id, user1, user2 = _create_doc_and_users(
        models,
        u1_perms={"checkout": True, "checkin": True},
        u2_perms={"checkin": True, "override": False},
    )
    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=5)
    session.commit()
    session.close()
    _login(client, user2)
    resp = client.post(f"/api/documents/{doc_id}/checkin")
    assert resp.status_code == 403


def test_force_checkin_allowed_with_override(client, app_models):
    app_module, models = app_models
    doc_id, user1, user2 = _create_doc_and_users(
        models,
        u1_perms={"checkout": True, "checkin": True},
        u2_perms={"checkin": True, "override": True},
    )
    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=5)
    session.commit()
    session.close()
    _login(client, user2)
    resp = client.post(f"/api/documents/{doc_id}/checkin")
    assert resp.status_code == 200

def test_force_checkin_button_visibility(client, app_models):
    app_module, models = app_models
    storage = importlib.import_module("storage")
    storage.storage_client.generate_presigned_url = lambda *a, **k: None
    doc_id, user1, user2 = _create_doc_and_users(
        models,
        u1_perms={"checkout": True, "checkin": True},
        u2_perms={"checkin": True, "override": False},
    )
    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=5)
    session.commit()
    session.close()

    _login(client, user2, roles=["reader"])
    resp = client.get(f"/documents/{doc_id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Force Check in" not in body

    _login(client, user2, roles=["reader", "quality_admin"])
    resp = client.get(f"/documents/{doc_id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Force Check in" in body


def test_unlock_document_admin(client, app_models):
    app_module, models = app_models
    doc_id, user1, user2 = _create_doc_and_users(models)
    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=5)
    session.commit()
    session.close()

    _login(client, user2, roles=["quality_admin"])
    resp = client.post(f"/api/documents/{doc_id}/unlock")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "unlocked"}

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    assert doc.locked_by is None
    assert doc.lock_expires_at is None
    session.close()


def test_unlock_document_forbidden(client, app_models):
    app_module, models = app_models
    doc_id, user1, user2 = _create_doc_and_users(models)
    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    doc.locked_by = user1
    doc.lock_expires_at = datetime.utcnow() + timedelta(minutes=5)
    session.commit()
    session.close()

    _login(client, user2)
    resp = client.post(f"/api/documents/{doc_id}/unlock")
    assert resp.status_code == 403

    session = models.SessionLocal()
    doc = session.get(models.Document, doc_id)
    assert doc.locked_by == user1
    session.close()
