import os
import importlib
from datetime import datetime

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_s3


def test_move_to_archive_retains_object_and_lists():
    os.environ.pop("S3_ENDPOINT", None)
    os.environ["S3_ACCESS_KEY"] = "test"
    os.environ["S3_SECRET_KEY"] = "test"
    os.environ["S3_BUCKET_MAIN"] = "qdms"
    os.environ["S3_BUCKET_ARCHIVE"] = "qdms-archive"

    with mock_s3():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="qdms", ObjectLockEnabledForBucket=True)
        client.create_bucket(Bucket="qdms-archive", ObjectLockEnabledForBucket=True)
        client.put_object(Bucket="qdms", Key="sample.txt", Body=b"data")

        storage = importlib.reload(importlib.import_module("storage"))
        dest_key = storage.move_to_archive("sample.txt", retention_days=1)

        head = client.head_object(Bucket="qdms-archive", Key=dest_key)
        assert head["ObjectLockMode"] == "COMPLIANCE"
        assert head["ObjectLockRetainUntilDate"] > datetime.utcnow()

        assert dest_key in storage.list_archived()

