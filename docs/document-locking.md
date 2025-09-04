# Document Locking API

When a document is checked out via `POST /api/documents/<id>/checkout`, the response includes information about the lock:

```json
{
  "locked_by": <user_id>,
  "locked_until": "<ISO timestamp>",
  "lock_expires_at": "<ISO timestamp>"
}
```

`locked_until` is the preferred key. `lock_expires_at` is provided for backward compatibility and will be removed in a future release.
