import os
import smtplib
import json
from email.message import EmailMessage
from queue import Queue
import requests
from models import get_session, User, UserSetting, Notification

SMTP_SERVER = os.environ.get("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_SENDER = os.environ.get("SMTP_SENDER", "noreply@example.com")
# Default webhook URL used when a user has webhook notifications enabled
# but has not configured a personal URL.
WEBHOOK_URL_DEFAULT = os.environ.get("WEBHOOK_URL_DEFAULT")

# --- In-memory channel management for SSE clients ---
_channels = {}


def subscribe(user_id: int) -> Queue:
    """Register an SSE client for the given user."""
    q = Queue()
    _channels.setdefault(user_id, []).append(q)
    return q


def unsubscribe(user_id: int, q: Queue) -> None:
    """Remove an SSE client from the registry."""
    if user_id in _channels and q in _channels[user_id]:
        _channels[user_id].remove(q)

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
    """Deliver a notification to the specified user.

    When webhook notifications are enabled but the user does not specify a
    webhook URL, this function falls back to ``WEBHOOK_URL_DEFAULT`` if it is
    defined.
    """
    session = get_session()
    try:
        user = session.get(User, user_id)
        settings = session.query(UserSetting).filter_by(user_id=user_id).first()
        user_email = user.email if user else None

        note = Notification(user_id=user_id, message=body)
        session.add(note)
        session.commit()
        payload = json.dumps({"id": note.id, "message": note.message})

        channels = _channels.get(user_id, [])
        for q in channels:
            q.put(payload)
        if channels:
            note.read = True
            session.commit()
    finally:
        session.close()
    if not user:
        return
    if settings:
        if settings.email_enabled and user_email:
            send_email(user_email, subject, body)
        if settings.webhook_enabled:
            # Use a user-specific webhook URL if provided, otherwise fall back
            # to the globally configured default. The webhook is only invoked
            # when an actual URL is available.
            webhook_url = settings.webhook_url or WEBHOOK_URL_DEFAULT
            if webhook_url:
                send_webhook(webhook_url, body)
    else:
        if user_email:
            send_email(user_email, subject, body)

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
