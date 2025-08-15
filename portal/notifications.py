import os
import smtplib
from email.message import EmailMessage
import requests
from models import get_session, User, UserSetting

SMTP_SERVER = os.environ.get("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_SENDER = os.environ.get("SMTP_SENDER", "noreply@example.com")

def send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_SENDER
    msg["To"] = to
    msg.set_content(body)
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.send_message(msg)

def send_webhook(url: str, message: str) -> None:
    requests.post(url, json={"text": message})

def notify_user(user_id: int, subject: str, body: str) -> None:
    session = get_session()
    try:
        user = session.get(User, user_id)
        settings = session.query(UserSetting).filter_by(user_id=user_id).first()
    finally:
        session.close()
    if not user:
        return
    if settings:
        if settings.email_enabled and user.email:
            send_email(user.email, subject, body)
        if settings.webhook_enabled and settings.webhook_url:
            send_webhook(settings.webhook_url, body)
    else:
        if user.email:
            send_email(user.email, subject, body)

def notify_approval_queue(doc, approver_ids):
    subject = f"Document {doc.title} awaiting approval"
    body = f"Document {doc.title} is waiting for your approval."
    for uid in approver_ids:
        notify_user(uid, subject, body)

def notify_revision_time(doc, user_ids):
    subject = f"Document {doc.title} revised"
    body = f"Document {doc.title} has a new revision {doc.major_version}.{doc.minor_version}."
    for uid in user_ids:
        notify_user(uid, subject, body)

def notify_mandatory_read(doc, user_ids):
    subject = f"Document {doc.title} requires your acknowledgement"
    body = f"Please read and acknowledge document {doc.title}."
    for uid in user_ids:
        notify_user(uid, subject, body)
