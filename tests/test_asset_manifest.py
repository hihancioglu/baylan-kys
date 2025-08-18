import json
import os
from pathlib import Path

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")


def test_base_js_present_in_manifest():
    manifest_path = Path("portal/static/dist/manifest.json")
    data = json.loads(manifest_path.read_text())

    assert "base.js" in data, "base.js missing from asset manifest"

    built_file = Path("portal/static/dist") / data["base.js"]
    assert built_file.exists(), "built base.js asset missing"

