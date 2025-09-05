import importlib


def test_signed_url_expire_seconds_env(monkeypatch):
    monkeypatch.setenv("STORAGE__TYPE", "fs")
    monkeypatch.setenv("STORAGE__SIGNED_URL_EXPIRE_SECONDS", "1234")
    import portal.storage as storage
    importlib.reload(storage)
    assert storage.StorageBackend.signed_url_expire_seconds == 1234


def test_max_presign_size_default(monkeypatch):
    monkeypatch.setenv("STORAGE__TYPE", "fs")
    import portal.storage as storage
    importlib.reload(storage)
    assert storage.StorageBackend.max_presign_size == 200 * 1024 * 1024
