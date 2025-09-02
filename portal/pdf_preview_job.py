"""Background job to generate PDF previews for documents."""
from __future__ import annotations

import os
import tempfile
from typing import Any

from signing import convert_to_pdf
from storage import storage_client

try:  # pragma: no cover - real redis only used in production
    from redis import Redis
    from rq import Queue
except Exception:  # pragma: no cover - fallback stubs for tests
    from rq_stub import Queue  # type: ignore

    class Redis:  # type: ignore
        def __init__(self, *_, **__):
            pass

        @classmethod
        def from_url(cls, url: str):
            return cls()


redis_conn = Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0")),
    password=os.getenv("REDIS_PASSWORD"),
)

queue: Queue = Queue("pdf_previews", connection=redis_conn)


def generate_preview(doc_id: int, version: str, key: str) -> None:
    """Download a document, convert to PDF, and store the preview."""
    # Ensure the configured preview bucket is available before doing any work.
    # This raises an informative error if misconfigured, helping operators
    # detect missing ``S3_BUCKET_PREVIEWS`` or permission issues early.
    storage_client.verify_preview_bucket()

    obj = storage_client.get_object(Key=key, Bucket=storage_client.bucket_main)
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, os.path.basename(key))
        with open(src_path, "wb") as f:
            f.write(obj["Body"].read())
        pdf_path = convert_to_pdf(src_path, tmpdir)
        dest_key = f"previews/{doc_id}/{version}.pdf"
        with open(pdf_path, "rb") as f:
            storage_client.put_object(
                Key=dest_key,
                Body=f,
                Bucket=storage_client.bucket_previews,
                ContentType="application/pdf",
            )


def enqueue_preview(doc_id: int, version: str, key: str) -> None:
    """Queue a job to generate a PDF preview for a document."""
    try:
        queue.enqueue(generate_preview, doc_id, version, key)
    except Exception:  # pragma: no cover - queue backend unavailable
        pass


__all__ = ["enqueue_preview", "generate_preview", "queue"]
