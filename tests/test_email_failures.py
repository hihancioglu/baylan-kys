import importlib
import sys
from unittest.mock import MagicMock, patch


def test_send_email_connection_error_suppressed():
    rq = importlib.import_module("rq_stub")
    sys.modules["rq"] = rq
    notifications = importlib.import_module("notifications")
    notifier = notifications.EmailNotifier()
    fake_user = MagicMock(email="user@example.com")
    with patch("notifications.smtplib.SMTP", side_effect=ConnectionRefusedError):
        notifier.send(fake_user, "Subject", "Body")

