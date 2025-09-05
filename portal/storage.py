"""Pluggable storage backends.

This module provides a small abstraction layer so the application can work
with different storage providers (currently MinIO/S3 and the local
filesystem).  Callers interact with a single ``storage_client`` instance which
implements the :class:`StorageBackend` interface regardless of the underlying
backend.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
import base64
import hashlib

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, NoCredentialsError


def _env(name: str, default: str | None = None) -> str | None:
    """Fetch configuration values using ``storage.foo`` style names.

    Environment variables use ``STORAGE__FOO`` to mirror nested configuration
    (similar to how libraries like Dynaconf expose settings).
    """

    return os.getenv(name.replace(".", "__").upper(), default)


class StorageBackend:
    """Simple interface all storage backends must implement."""

    bucket_main: str | None = None
    bucket_archive: str | None = None
    bucket_previews: str | None = None
    archive_prefix: str = _env("archive.prefix", "archive/") or "archive/"
    signed_url_expire_seconds: int = int(_env("storage.signed_url_expire_seconds", "3600") or "3600")
    # Maximum object size (in bytes) allowed for presigned downloads.
    max_presign_size: int = 200 * 1024 * 1024  # 200MB
    # -- basic primitives -------------------------------------------------
    def put(self, *args, **kwargs):  # pragma: no cover - interface only
        raise NotImplementedError

    def get(self, *args, **kwargs):  # pragma: no cover - interface only
        raise NotImplementedError

    def copy(self, *args, **kwargs):  # pragma: no cover - interface only
        raise NotImplementedError

    def delete(self, *args, **kwargs):  # pragma: no cover - interface only
        raise NotImplementedError

    def head(self, *args, **kwargs):  # pragma: no cover - interface only
        raise NotImplementedError

    def list(self, *args, **kwargs):  # pragma: no cover - interface only
        raise NotImplementedError

    def generate_presigned_url(  # pragma: no cover - interface only
        self, key: str, expires_in: int | None = None, bucket: str | None = None
    ) -> str | None:
        raise NotImplementedError

    def move_to_archive(  # pragma: no cover - interface only
        self, object_key: str, retention_days: int
    ) -> str:
        raise NotImplementedError

    def list_archived(self) -> list[str]:  # pragma: no cover - interface only
        raise NotImplementedError

    def verify_preview_bucket(self) -> None:  # pragma: no cover - interface only
        """Ensure the preview bucket is configured and accessible."""
        return None

    # -- S3-style aliases -------------------------------------------------
    def _add_aliases(self) -> None:
        """Expose historical boto3-style method names."""

        self.put_object = self.put
        self.get_object = self.get
        self.copy_object = self.copy
        self.delete_object = self.delete
        self.head_object = self.head
        self.list_objects_v2 = self.list


class MinIOBackend(StorageBackend):
    """Storage backend backed by MinIO or any S3 compatible service."""

    def __init__(self) -> None:
        self.endpoint = os.getenv("S3_ENDPOINT")
        self.public_endpoint = os.getenv("S3_PUBLIC_ENDPOINT")
        self.access_key = os.getenv("S3_ACCESS_KEY") or os.getenv(
            "S3_ACCESS_KEY_ID"
        )
        self.secret_key = os.getenv("S3_SECRET_KEY") or os.getenv(
            "S3_SECRET_ACCESS_KEY"
        )
        self.bucket_main = os.getenv("S3_BUCKET_MAIN") or os.getenv("S3_BUCKET")
        self.bucket_archive = os.getenv("S3_BUCKET_ARCHIVE") or self.bucket_main
        self.bucket_previews = os.getenv("S3_BUCKET_PREVIEWS") or self.bucket_main

        self.client = boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            config=Config(signature_version="s3v4"),
        )

        if self.public_endpoint:
            self.public_client = boto3.client(
                "s3",
                endpoint_url=self.public_endpoint,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                config=Config(signature_version="s3v4"),
            )
        else:
            self.public_client = self.client

        self._add_aliases()
        self._ensure_buckets()

    def _ensure_buckets(self) -> None:
        """Create required buckets on startup if they do not exist.

        This mirrors the bucket setup performed by the Docker ``minio-setup``
        service so that running the application outside Docker still works
        without manual bucket creation.
        """

        try:
            existing = {
                b["Name"] for b in self.client.list_buckets().get("Buckets", [])
            }
        except Exception:
            existing = set()

        required = {
            self.bucket_main,
            self.bucket_archive,
            self.bucket_previews,
        }

        for bucket in filter(None, required):
            if bucket in existing:
                continue
            try:
                create_kwargs: dict[str, Any] = {}
                if bucket in {self.bucket_main, self.bucket_archive}:
                    create_kwargs["ObjectLockEnabledForBucket"] = True
                self.client.create_bucket(Bucket=bucket, **create_kwargs)
                self.client.put_bucket_versioning(
                    Bucket=bucket,
                    VersioningConfiguration={"Status": "Enabled"},
                )
            except Exception:
                # Ignore failures so a missing permission doesn't break the app
                pass

    def verify_preview_bucket(self) -> None:
        """Validate that the preview bucket exists and is accessible."""
        if not self.bucket_previews:
            raise RuntimeError(
                "Preview bucket not configured. Set S3_BUCKET_PREVIEWS or S3_BUCKET_MAIN."
            )
        if not hasattr(self.client, "head_bucket"):
            # Simplified stub clients used in tests may not implement this call.
            return
        try:
            # ``head_bucket`` checks both existence and access permissions.
            self.client.head_bucket(Bucket=self.bucket_previews)
        except Exception as exc:  # pragma: no cover - network/credentials
            raise RuntimeError(
                f"Unable to access preview bucket '{self.bucket_previews}'"
            ) from exc

    # -- basic wrappers -------------------------------------------------
    def put(self, Bucket: str | None = None, **kwargs):
        return self.client.put_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def get(self, Bucket: str | None = None, **kwargs):
        return self.client.get_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def copy(self, Bucket: str | None = None, **kwargs):
        return self.client.copy_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def delete(self, Bucket: str | None = None, **kwargs):
        return self.client.delete_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def head(self, Bucket: str | None = None, **kwargs):
        return self.client.head_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def list(self, Bucket: str | None = None, **kwargs):
        return self.client.list_objects_v2(Bucket=Bucket or self.bucket_main, **kwargs)

    def generate_presigned_url(
        self, key: str, expires_in: int | None = None, bucket: str | None = None
    ) -> str | None:
        bucket_name = bucket or self.bucket_main or "local"
        try:
            head = self.client.head_object(Bucket=bucket_name, Key=key)
            if head.get("ContentLength", 0) > self.max_presign_size:
                return None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("404", "NoSuchKey"):
                return None
            # For other client errors, continue and attempt to generate a URL.
        except Exception:
            # If the object cannot be inspected, continue and attempt to
            # generate a URL. The call below may still fail depending on the
            # underlying credentials, but this mirrors previous behavior.
            pass
        try:
            url = self.public_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": bucket_name,
                    "Key": key,
                    "ResponseCacheControl": "public, max-age=86400",
                },
                ExpiresIn=expires_in or self.signed_url_expire_seconds,
            )
        except NoCredentialsError:
            base = self.public_endpoint or self.endpoint
            if base:
                return f"{base.rstrip('/')}/{bucket_name}/{key}"
            return None

        return url

    # -- higher level helpers ------------------------------------------
    def move_to_archive(self, object_key: str, retention_days: int) -> str:
        """Copy an object to the archive prefix and delete the original."""

        dest_key = f"{self.archive_prefix}{object_key.split('/')[-1]}"
        retain_until = datetime.utcnow() + timedelta(days=retention_days)
        obj = self.client.get_object(Bucket=self.bucket_main, Key=object_key)
        body = obj["Body"].read()
        md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
        self.client.put_object(
            Bucket=self.bucket_archive,
            Key=dest_key,
            Body=body,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
            ContentMD5=md5,
        )
        self.delete(Key=object_key, Bucket=self.bucket_main)
        return dest_key

    def list_archived(self) -> list[str]:
        resp = self.list(Prefix=self.archive_prefix, Bucket=self.bucket_archive)
        return [obj["Key"] for obj in resp.get("Contents", [])]


class FSBackend(StorageBackend):
    """Filesystem storage served via an Nginx alias."""

    def __init__(self, base_path: str | None = None, public_url: str | None = None) -> None:
        self.base_path = Path(base_path or _env("storage.fs_path", "/tmp/files")).resolve()
        self.public_url = (public_url or _env("storage.fs_public_url", "/fs")).rstrip("/")
        self.base_path.mkdir(parents=True, exist_ok=True)

        self.bucket_main = None  # kept for interface compatibility
        self.bucket_archive = None
        self.bucket_previews = None

        self._add_aliases()

    # helper ------------------------------------------------------------
    def _full_path(self, key: str) -> Path:
        return self.base_path / key

    # -- basic wrappers -------------------------------------------------
    def put(self, Key: str, Body: bytes | Any, **kwargs):
        path = self._full_path(Key)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = Body.read() if hasattr(Body, "read") else Body
        with open(path, "wb") as f:
            f.write(data)
        return {}

    def get(self, Key: str, **kwargs):
        path = self._full_path(Key)
        return {"Body": open(path, "rb")}

    def copy(self, CopySource: dict | str, Key: str, **kwargs):
        if isinstance(CopySource, dict):
            src_key = CopySource.get("Key")
        else:
            src_key = str(CopySource)
        src = self._full_path(src_key)
        dest = self._full_path(Key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        return {}

    def delete(self, Key: str, **kwargs):
        path = self._full_path(Key)
        if path.exists():
            path.unlink()
        return {}

    def head(self, Key: str, **kwargs):
        path = self._full_path(Key)
        if not path.exists():
            raise FileNotFoundError(Key)
        return {"ContentLength": path.stat().st_size}

    def list(self, Prefix: str = "", **kwargs):
        prefix_path = self._full_path(Prefix)
        contents = []
        if prefix_path.exists():
            for file in prefix_path.rglob("*"):
                if file.is_file():
                    rel = file.relative_to(self.base_path).as_posix()
                    contents.append({"Key": rel})
        return {"Contents": contents}

    def generate_presigned_url(
        self, key: str, expires_in: int | None = None, bucket: str | None = None
    ) -> str | None:
        path = self._full_path(key)
        if not path.exists() or path.stat().st_size > self.max_presign_size:
            return None
        return f"{self.public_url}/{key}"

    # -- higher level helpers ------------------------------------------
    def move_to_archive(self, object_key: str, retention_days: int) -> str:
        dest_key = f"{self.archive_prefix}{Path(object_key).name}"
        self.copy(object_key, dest_key)
        self.delete(object_key)
        return dest_key

    def list_archived(self) -> list[str]:
        resp = self.list(self.archive_prefix)
        return [obj["Key"] for obj in resp.get("Contents", [])]


# -- backend loader --------------------------------------------------------
def _load_backend() -> StorageBackend:
    backend_type = (_env("storage.type", "minio") or "minio").lower()
    if backend_type == "fs":
        return FSBackend()
    return MinIOBackend()


# Global instance used throughout the app
storage_client: StorageBackend = _load_backend()


# Backwards compatible module-level helpers ---------------------------------
def move_to_archive(object_key: str, retention_days: int) -> str:
    return storage_client.move_to_archive(object_key, retention_days)


def list_archived() -> list[str]:
    return storage_client.list_archived()


def generate_presigned_url(key: str, expires_in: int | None = None) -> str | None:
    return storage_client.generate_presigned_url(key, expires_in)


__all__ = [
    "StorageBackend",
    "MinIOBackend",
    "FSBackend",
    "storage_client",
    "move_to_archive",
    "list_archived",
    "generate_presigned_url",
]

