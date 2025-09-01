# Notification Configuration

The following environment variables control email and webhook notifications:

- `SMTP_SERVER`: Hostname of the SMTP server used to send emails.
- `SMTP_PORT`: Port number for the SMTP server (e.g., 587 for TLS).
- `SMTP_SENDER`: Default `From` address for outgoing emails.
- `ENABLE_WEBHOOK_NOTIFIER`: Enable per-user webhooks when set to `1`.
- `WEBHOOK_URL_DEFAULT`: Fallback webhook URL used when a user's setting does not provide one.
- `REDIS_HOST`: Hostname of the Redis server used for the notifications queue.
- `REDIS_PORT`: Port number for the Redis server.
- `REDIS_DB`: Redis database number that stores queued notifications.
- `REDIS_PASSWORD`: Password for the Redis server, if authentication is required.

### REST polling

Unread notifications and dashboard counts can be retrieved by polling the
`/api/notifications` and `/api/counts` endpoints. Clients poll at an interval
configured by the `POLL_INTERVAL_MS` environment variable (default 10000 ms).
Each request to `/api/notifications` marks returned notifications as read.

### Server-Sent Events

The dashboard can stream card updates over Server-Sent Events from
`/api/dashboard/stream`. When the browser supports `hx-sse`, the dashboard
connects to this stream and receives real-time updates. If SSE is not
available, the templates fall back to polling every `POLL_INTERVAL_MS`
milliseconds.

### Testing

Unit tests exercise notification triggers with a stubbed RQ queue. Run them
with:

```
pytest tests/test_version_upload_notifications.py \
       tests/test_checkout_notifications.py \
       tests/test_document_notifications.py
```

Integration tests cover dashboard behaviour, including pending approvals and
recent changes cards:

```
pytest tests/test_z_dashboard_api.py::test_api_pending_approvals_includes_unassigned_for_role_user \
       tests/test_dashboard_cards.py::test_recent_changes_shows_version_numbers
```
