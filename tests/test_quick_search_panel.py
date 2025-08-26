import importlib
import re


def _client():
    app_module = importlib.import_module("app")
    return app_module.app.test_client()


def _assert_panel_hidden(html: str):
    pattern = r'id="quick-search-panel"[^>]*class="[^"]*\bd-none\b'
    assert re.search(pattern, html)


def test_terminology_page_panel_hidden():
    client = _client()
    resp = client.get("/terminology")
    assert resp.status_code == 200
    _assert_panel_hidden(resp.get_data(as_text=True))


def test_help_page_panel_hidden():
    client = _client()
    resp = client.get("/help")
    assert resp.status_code == 200
    _assert_panel_hidden(resp.get_data(as_text=True))

