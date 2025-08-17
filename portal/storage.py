"""Utility helpers for S3/MinIO archival storage."""

import os
from datetime import datetime, timedelta
import boto3
from botocore.client import Config
from botocore.exceptions import NoCredentialsError

S3_ENDPOINT = os.getenv("S3_ENDPOINT")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY") or os.getenv("S3_ACCESS_KEY_ID")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY") or os.getenv("S3_SECRET_ACCESS_KEY")
S3_BUCKET = os.getenv("S3_BUCKET") or os.getenv("S3_BUCKET_MAIN")
ARCHIVE_PREFIX = os.getenv("ARCHIVE_PREFIX", "archive/")
SIGNED_URL_EXPIRE_SECONDS = int(os.getenv("SIGNED_URL_EXPIRE_SECONDS", "3600"))

_s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    config=Config(signature_version="s3v4"),
)


def move_to_archive(object_key: str, retention_days: int) -> str:
    """Copy an object to the archive prefix with a WORM lock and delete the original."""
    dest_key = f"{ARCHIVE_PREFIX}{object_key.split('/')[-1]}"
    retain_until = datetime.utcnow() + timedelta(days=retention_days)
    _s3.copy_object(
        Bucket=S3_BUCKET,
        CopySource={"Bucket": S3_BUCKET, "Key": object_key},
        Key=dest_key,
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retain_until,
    )
    _s3.delete_object(Bucket=S3_BUCKET, Key=object_key)
    return dest_key


def list_archived() -> list[str]:
    """Return keys of archived objects."""
    resp = _s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=ARCHIVE_PREFIX)
    return [obj["Key"] for obj in resp.get("Contents", [])]


def generate_presigned_url(key: str, expires_in: int | None = None) -> str | None:
    """Generate a presigned download URL for an object."""
    try:
        return _s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": key},
            ExpiresIn=expires_in or SIGNED_URL_EXPIRE_SECONDS,
        )
    except NoCredentialsError:
        return None
