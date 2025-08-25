# Notification Configuration

The following environment variables control email and webhook notifications:

- `SMTP_SERVER`: Hostname of the SMTP server used to send emails.
- `SMTP_PORT`: Port number for the SMTP server (e.g., 587 for TLS).
- `SMTP_SENDER`: Default `From` address for outgoing emails.
- `WEBHOOK_URL_DEFAULT`: Fallback webhook URL used when no specific webhook is configured.

### REST polling

Unread notifications and dashboard counts can be retrieved by polling the
`/api/notifications` and `/api/counts` endpoints.  Clients poll at an interval
configured by the `POLL_INTERVAL_MS` environment variable (default 5000 ms).
Each request to `/api/notifications` marks returned notifications as read.
