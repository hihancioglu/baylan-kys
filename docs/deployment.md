# Deployment Notes

## PDF Preview Requirements

- Set either `S3_BUCKET_PREVIEWS` or `S3_BUCKET_MAIN` so `portal/storage.py` can access a preview bucket.
- Run an RQ worker for the `pdf_previews` queue:
  ```bash
  rq worker pdf_previews
  ```
- After a document is uploaded, `pdf_preview_job.enqueue_preview` creates `previews/<doc_id>/<version>.pdf` in the preview bucket.

## Scheduled Jobs

- Ensure the scheduler container (or an equivalent cron setup) runs maintenance tasks.
- The scheduler now executes `clear_locks_job.py` every 5 minutes to release expired document locks:
  ```bash
  ( while :; do python clear_locks_job.py; sleep 300; done )
  ```
  Configure your deployment to run this command periodically if not using `docker-compose`.

