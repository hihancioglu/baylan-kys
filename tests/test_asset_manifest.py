import json
import os
import sys
from pathlib import Path

os.environ.setdefault("ONLYOFFICE_INTERNAL_URL", "http://oo")
os.environ.setdefault("ONLYOFFICE_PUBLIC_URL", "http://oo-public")
os.environ.setdefault("ONLYOFFICE_JWT_SECRET", "secret")

def test_app_loads_when_base_js_missing():
    manifest_path = Path("portal/static/dist/manifest.json")
    original = manifest_path.read_text()
    data = json.loads(original)
    data.pop("base.js", None)
    manifest_path.write_text(json.dumps(data))

    try:
        sys.modules.pop("portal.app", None)
        import portal.app as appmodule
        assert appmodule._asset_manifest["base.js"] == "base.js"
    finally:
        manifest_path.write_text(original)
        sys.modules.pop("portal.app", None)
        import portal.app  # restore original module
