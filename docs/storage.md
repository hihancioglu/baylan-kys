# Storage Backends

The portal supports pluggable storage and selects the implementation via the
`STORAGE__TYPE` environment variable.  Two backends are available:

- `minio` *(default)* – S3-compatible storage such as MinIO.
- `fs` – the local filesystem served by Nginx.

## MinIO / S3

When `STORAGE__TYPE` is `minio`, the following variables must be set:

- `S3_ENDPOINT` – URL of the S3 service.
- `S3_PUBLIC_ENDPOINT` *(optional)* – external URL or reverse-proxy path to expose in presigned links; this must be reachable by clients.
- `S3_ACCESS_KEY` / `S3_ACCESS_KEY_ID`
- `S3_SECRET_KEY` / `S3_SECRET_ACCESS_KEY`
- `S3_BUCKET_MAIN` / `S3_BUCKET` – bucket for uploaded files.
- `S3_BUCKET_ARCHIVE` *(optional)* – bucket for archived items, defaults to the main bucket.
- `S3_BUCKET_PREVIEWS` *(optional)* – bucket for preview assets, defaults to the main bucket.

`STORAGE__SIGNED_URL_EXPIRE_SECONDS` controls the TTL of presigned URLs generated for
clients.  It defaults to one hour.

Presigned URLs are only generated for objects up to 200 MB (`max_presign_size`).
To download larger files or hide the storage endpoint, append `?via=proxy` to a
download URL to stream the file through the portal instead of redirecting.

When `S3_PUBLIC_ENDPOINT` is set, the hostname of presigned URLs is replaced
with this value.  This allows clients to download files even when the internal
S3 endpoint is not reachable from their network, provided the value points to
an externally accessible host or path.

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

Signed URL TTL is still governed by `STORAGE__SIGNED_URL_EXPIRE_SECONDS`, though the
filesystem backend simply returns the public URL without signing. The 200 MB
`max_presign_size` limit and `?via=proxy` download option also apply here.

