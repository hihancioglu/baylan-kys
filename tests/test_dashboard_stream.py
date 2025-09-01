import os
import importlib

import pytest


@pytest.fixture
def client():
    os.environ.setdefault("S3_ENDPOINT", "http://s3")
    a = importlib.import_module("app")
    return a.app.test_client()


def _login(client):
    with client.session_transaction() as sess:
        sess["user"] = {"id": 1, "name": "Tester"}
        sess["roles"] = ["reader"]


def test_dashboard_polling_and_sse(client):
    _login(client)
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "every 10s" in html
    assert 'hx-sse="connect:/api/dashboard/stream"' in html
    assert 'hx-sse="swap:pending"' in html


def test_dashboard_sse_stream(client):
    _login(client)
    resp = client.get("/api/dashboard/stream")
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"
    first = next(resp.response).decode()
    assert "event: pending" in first
