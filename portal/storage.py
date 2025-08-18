"""Utility helpers for S3/MinIO archival storage."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

import boto3
from botocore.client import Config
from botocore.exceptions import NoCredentialsError


class StorageClient:
    """Encapsulates interactions with S3/MinIO."""

    def __init__(self) -> None:
        self.endpoint = os.getenv("S3_ENDPOINT")
        self.access_key = os.getenv("S3_ACCESS_KEY") or os.getenv(
            "S3_ACCESS_KEY_ID"
        )
        self.secret_key = os.getenv("S3_SECRET_KEY") or os.getenv(
            "S3_SECRET_ACCESS_KEY"
        )
        self.bucket_main = os.getenv("S3_BUCKET_MAIN") or os.getenv("S3_BUCKET")
        self.bucket_archive = os.getenv("S3_BUCKET_ARCHIVE") or self.bucket_main
        self.bucket_previews = os.getenv("S3_BUCKET_PREVIEWS") or self.bucket_main
        self.archive_prefix = os.getenv("ARCHIVE_PREFIX", "archive/")
        self.signed_url_expire_seconds = int(
        
            os.getenv("SIGNED_URL_EXPIRE_SECONDS", "3600")
        )

        self.client = boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            config=Config(signature_version="s3v4"),
        )

    # -- basic wrappers -------------------------------------------------
    def put_object(self, Bucket: str | None = None, **kwargs):
        return self.client.put_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def get_object(self, Bucket: str | None = None, **kwargs):
        return self.client.get_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def copy_object(self, Bucket: str | None = None, **kwargs):
        return self.client.copy_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def delete_object(self, Bucket: str | None = None, **kwargs):
        return self.client.delete_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def head_object(self, Bucket: str | None = None, **kwargs):
        return self.client.head_object(Bucket=Bucket or self.bucket_main, **kwargs)

    def list_objects_v2(self, Bucket: str | None = None, **kwargs):
        return self.client.list_objects_v2(Bucket=Bucket or self.bucket_main, **kwargs)

    def generate_presigned_url(
        self, key: str, expires_in: int | None = None, bucket: str | None = None
    ) -> str | None:
        bucket_name = bucket or self.bucket_main or "local"
        try:
            return self.client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket_name, "Key": key},
                ExpiresIn=expires_in or self.signed_url_expire_seconds,
            )
        except NoCredentialsError:
            if self.endpoint:
                return f"{self.endpoint}/{bucket_name}/{key}"
            return None

    # -- higher level helpers ------------------------------------------
    def move_to_archive(self, object_key: str, retention_days: int) -> str:
        """Copy an object to the archive prefix with a WORM lock and delete the original."""

        dest_key = f"{self.archive_prefix}{object_key.split('/')[-1]}"
        retain_until = datetime.utcnow() + timedelta(days=retention_days)
        self.copy_object(
            CopySource={"Bucket": self.bucket_main, "Key": object_key},
            Key=dest_key,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
        )
        self.delete_object(Key=object_key)
        return dest_key

    def list_archived(self) -> list[str]:
        resp = self.list_objects_v2(Prefix=self.archive_prefix)
        return [obj["Key"] for obj in resp.get("Contents", [])]


# Global instance used throughout the app
storage_client = StorageClient()


# Backwards compatible module-level helpers ---------------------------------
def move_to_archive(object_key: str, retention_days: int) -> str:
    return storage_client.move_to_archive(object_key, retention_days)


def list_archived() -> list[str]:
    return storage_client.list_archived()


def generate_presigned_url(key: str, expires_in: int | None = None) -> str | None:
    return storage_client.generate_presigned_url(key, expires_in)

