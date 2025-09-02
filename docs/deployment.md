# Deployment Notes

## PDF Preview Requirements

- Set either `S3_BUCKET_PREVIEWS` or `S3_BUCKET_MAIN` so `portal/storage.py` can access a preview bucket.
- Run an RQ worker for the `pdf_previews` queue:
  ```bash
  rq worker pdf_previews
  ```
- After a document is uploaded, `pdf_preview_job.enqueue_preview` creates `previews/<doc_id>/<version>.pdf` in the preview bucket.

