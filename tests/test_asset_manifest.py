"""Verify that key static files are built without relying on a manifest."""

import os


def test_static_assets_present():
    base = os.path.join('portal', 'static', 'dist')
    expected_files = ['base.js', 'app.js', 'app.css']
    for fname in expected_files:
        path = os.path.join(base, fname)
        assert os.path.exists(path), f"{fname} missing"
        assert os.path.getsize(path) > 0, f"{fname} empty"
