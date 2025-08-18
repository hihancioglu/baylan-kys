from unittest.mock import patch

import notifications


def test_send_email_connection_error_suppressed():
    with patch('notifications.smtplib.SMTP', side_effect=ConnectionRefusedError):
        notifications.send_email('user@example.com', 'Subject', 'Body')

