import importlib
from pathlib import Path
from unittest.mock import patch


def _client():
    app_module = importlib.import_module("app")
    return app_module.app.test_client()


def test_help_route_missing_file_returns_error():
    client = _client()
    original_exists = Path.exists

    def fake_exists(self):
        if self.name == "help.md":
            return False
        return original_exists(self)

    with patch("app.Path.exists", fake_exists):
        resp = client.get("/help")

    assert resp.status_code == 200
    assert "İçerik bulunamadı" in resp.get_data(as_text=True)


def test_terminology_route_missing_file_returns_error():
    client = _client()
    original_exists = Path.exists

    def fake_exists(self):
        if self.name == "terminology.md":
            return False
        return original_exists(self)

    with patch("app.Path.exists", fake_exists):
        resp = client.get("/terminology")

    assert resp.status_code == 200
    assert "İçerik bulunamadı" in resp.get_data(as_text=True)


def test_help_route_renders_content_when_present():
    client = _client()
    original_read = Path.read_text

    def fake_read(self, encoding="utf-8"):
        if self.name == "help.md":
            return "yardim icerigi"
        return original_read(self, encoding=encoding)

    with patch("app.Path.read_text", fake_read):
        resp = client.get("/help")

    assert resp.status_code == 200
    assert "yardim icerigi" in resp.get_data(as_text=True)


def test_terminology_route_renders_content_when_present():
    client = _client()
    original_read = Path.read_text

    def fake_read(self, encoding="utf-8"):
        if self.name == "terminology.md":
            return "terminoloji icerigi"
        return original_read(self, encoding=encoding)

    with patch("app.Path.read_text", fake_read):
        resp = client.get("/terminology")

    assert resp.status_code == 200
    assert "terminoloji icerigi" in resp.get_data(as_text=True)

