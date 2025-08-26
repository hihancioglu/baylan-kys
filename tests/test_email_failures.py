import importlib
from unittest.mock import MagicMock, patch


def test_send_email_connection_error_suppressed():
    notifications = importlib.import_module("notifications")
    notifier = notifications.EmailNotifier()
    fake_user = MagicMock(email="user@example.com")
    with patch("notifications.smtplib.SMTP", side_effect=ConnectionRefusedError):
        notifier.send(fake_user, "Subject", "Body")

