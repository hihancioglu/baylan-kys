from types import SimpleNamespace
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "portal"))

import portal.storage as storage


def test_minio_public_endpoint(monkeypatch):
    monkeypatch.setenv("S3_ENDPOINT", "http://internal:9000")
    monkeypatch.setenv("S3_PUBLIC_ENDPOINT", "https://cdn.example.com")
    monkeypatch.setenv("S3_ACCESS_KEY", "key")
    monkeypatch.setenv("S3_SECRET_KEY", "secret")
    monkeypatch.setenv("S3_BUCKET_MAIN", "main")

    class DummyClient:
        def list_buckets(self):
            return {"Buckets": []}

        def create_bucket(self, **kwargs):
            pass

        def put_bucket_versioning(self, **kwargs):
            pass

        def head_object(self, Bucket, Key):
            return {"ContentLength": 1}

        def generate_presigned_url(self, *args, **kwargs):
            return "http://internal:9000/main/test.txt?X=1"

    monkeypatch.setattr(storage, "boto3", SimpleNamespace(client=lambda *a, **k: DummyClient()))

    backend = storage.MinIOBackend()
    url = backend.generate_presigned_url("test.txt")
    assert url == "https://cdn.example.com/main/test.txt?X=1"
