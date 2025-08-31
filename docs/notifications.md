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
`/api/notifications` and `/api/counts` endpoints.  Clients poll at an interval
configured by the `POLL_INTERVAL_MS` environment variable (default 5000 ms).
Each request to `/api/notifications` marks returned notifications as read.
