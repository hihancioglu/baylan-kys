# Storage Backends

The portal supports pluggable storage and selects the implementation via the
`STORAGE__TYPE` environment variable.  Two backends are available:

- `minio` *(default)* – S3-compatible storage such as MinIO.
- `fs` – the local filesystem served by Nginx.

## MinIO / S3

When `STORAGE__TYPE` is `minio`, the following variables must be set:

- `S3_ENDPOINT` – URL of the S3 service.
- `S3_ACCESS_KEY` / `S3_ACCESS_KEY_ID`
- `S3_SECRET_KEY` / `S3_SECRET_ACCESS_KEY`
- `S3_BUCKET_MAIN` / `S3_BUCKET` – bucket for uploaded files.
- `S3_BUCKET_ARCHIVE` *(optional)* – bucket for archived items, defaults to the main bucket.
- `S3_BUCKET_PREVIEWS` *(optional)* – bucket for preview assets, defaults to the main bucket.

`SIGNED_URL_EXPIRE_SECONDS` controls the TTL of presigned URLs generated for
clients.  It defaults to one hour.

## Filesystem

The filesystem backend stores files on disk and serves them through an Nginx
alias.  Configure the following variables:

- `STORAGE__FS_PATH` – absolute path where files are written.
- `STORAGE__FS_PUBLIC_URL` – URL prefix that Nginx exposes for the files.

Nginx must map the public URL to the path using an `alias`.  Example
configuration:

```nginx
location /fs {
    alias /var/lib/portal/files;
}
```

Signed URL TTL is still governed by `SIGNED_URL_EXPIRE_SECONDS`, though the
filesystem backend simply returns the public URL without signing.

