"""Notification dispatchers and queue integration.

This module defines a small notification framework used by the application to
deliver messages to users.  Notifications are sent asynchronously using an RQ
queue so that HTTP requests do not block while e‑mails or webhooks are sent.

The module exposes the :func:`notify_user` helper which enqueues a job for
delivery.  Actual delivery is handled by :func:`_send_notification` which is
executed by an RQ worker.  The worker will retry failed jobs up to three times
using RQ's built in :class:`rq.retry.Retry` mechanism.

Four notifier implementations are provided:

``EmailNotifier``
    Sends e‑mails using SMTP.

``SlackNotifier``
    Sends a message to a Slack channel using a webhook.

``TelegramNotifier``
    Uses the Telegram bot API to send a message to a chat.

``WebhookNotifier``
    POSTs a JSON payload to a configurable URL.

Notifier classes can be enabled or disabled using environment variables.  This
allows deployments to select the channels that are relevant for them without any
code changes.
"""

from __future__ import annotations

import logging
import os
import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage
from typing import Dict, Iterable, Tuple

import requests
from rq import Queue, Retry
from sqlalchemy.orm import sessionmaker

try:
    from redis import Redis
except ImportError:  # pragma: no cover - fallback stub for tests
    class Redis:  # type: ignore
        def __init__(self, *_, **__):
            pass

        @classmethod
        def from_url(cls, url: str):
            return cls()

from models import Notification, User, UserSetting, engine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Queue configuration
# ---------------------------------------------------------------------------

# Configure the notifications queue backed by Redis.  Tests may monkeypatch
# this queue with an in-memory implementation.
redis_conn = Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0")),
    password=os.getenv("REDIS_PASSWORD"),
)
queue: Queue = Queue("notifications", connection=redis_conn)


# ---------------------------------------------------------------------------
# Notifier interfaces
# ---------------------------------------------------------------------------

class Notifier(ABC):
    """Base class for notification backends.

    Sub-classes only need to implement :meth:`send`.  A convenience
    :meth:`prepare_message` helper is provided which performs basic ``str``
    templating and is shared by all notifiers.
    """

    def prepare_message(
        self, subject_template: str, body_template: str, **context: str
    ) -> Tuple[str, str]:
        """Return rendered ``subject`` and ``body`` strings.

        The default implementation performs simple ``str.format`` substitution.
        """

        subject = subject_template.format(**context)
        body = body_template.format(**context)
        return subject, body

    @abstractmethod
    def send(self, user: User, subject: str, body: str) -> None:
        """Send a notification to ``user``."""


class EmailNotifier(Notifier):
    """Send notifications via SMTP."""

    def __init__(self) -> None:
        self.server = os.getenv("SMTP_SERVER", "localhost")
        self.port = int(os.getenv("SMTP_PORT", "25"))
        self.sender = os.getenv("SMTP_SENDER", "noreply@example.com")

    def send(self, user: User, subject: str, body: str) -> None:  # pragma: no cover - network
        if not getattr(user, "email", None):
            return
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = user.email
        msg.set_content(body)
        try:
            with smtplib.SMTP(self.server, self.port) as smtp:
                smtp.send_message(msg)
        except Exception as exc:  # pragma: no cover - logging path isn't critical
            logger.warning("Failed to send email to %s: %s", user.email, exc)


class SlackNotifier(Notifier):
    """Send notifications to Slack via an incoming webhook."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def send(self, user: User, subject: str, body: str) -> None:  # pragma: no cover - network
        message = f"{subject}\n{body}"
        requests.post(self.webhook_url, json={"text": message})


class TelegramNotifier(Notifier):
    """Send notifications using the Telegram bot API."""

    def __init__(self, token: str, chat_id: str) -> None:
        self.token = token
        self.chat_id = chat_id

    def send(self, user: User, subject: str, body: str) -> None:  # pragma: no cover - network
        message = f"{subject}\n{body}"
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        requests.post(url, json={"chat_id": self.chat_id, "text": message})


class WebhookNotifier(Notifier):
    """Send notifications to an arbitrary webhook URL."""

    def __init__(self, url: str, user_id: int) -> None:
        self.url = url
        self.user_id = user_id

    def send(self, user: User, subject: str, body: str) -> None:  # pragma: no cover - network
        payload = {"user_id": self.user_id, "subject": subject, "body": body}
        requests.post(self.url, json=payload)


def _load_notifiers() -> Iterable[Tuple[str, Notifier]]:
    """Instantiate enabled notifiers based on environment variables."""

    enabled: Dict[str, Notifier] = {}
    if os.getenv("ENABLE_EMAIL_NOTIFIER", "1") in ("1", "true", "True"):
        enabled["email"] = EmailNotifier()

    if os.getenv("ENABLE_SLACK_NOTIFIER") in ("1", "true", "True"):
        url = os.getenv("SLACK_WEBHOOK_URL")
        if url:
            enabled["slack"] = SlackNotifier(url)

    if os.getenv("ENABLE_TELEGRAM_NOTIFIER") in ("1", "true", "True"):
        token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        if token and chat_id:
            enabled["telegram"] = TelegramNotifier(token, chat_id)

    return enabled.items()


# ---------------------------------------------------------------------------
# Notification job
# ---------------------------------------------------------------------------

def _send_notification(user_id: int, subject: str, body: str) -> None:
    """Job function executed by the worker to deliver a notification."""

    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        user = session.get(User, user_id)
        settings = session.query(UserSetting).filter_by(user_id=user_id).first()

        note = Notification(user_id=user_id, message=body)
        session.add(note)
        session.commit()

        email_enabled = settings.email_enabled if settings else True
        webhook_enabled = settings.webhook_enabled if settings else False
        webhook_url = settings.webhook_url if settings else None
        user_id_val = user.id if user else user_id
    finally:
        session.close()

    if not user:
        return

    notifiers = list(_load_notifiers())

    if (
        webhook_enabled
        and os.getenv("ENABLE_WEBHOOK_NOTIFIER") in ("1", "true", "True")
    ):
        url = webhook_url or os.getenv("WEBHOOK_URL_DEFAULT")
        if url:
            notifiers.append(("webhook", WebhookNotifier(url, user_id_val)))

    failures: Dict[str, Exception] = {}
    for channel, notifier in notifiers:
        if isinstance(notifier, EmailNotifier) and not email_enabled:
            continue
        try:
            notifier.send(user, subject, body)
        except Exception as exc:  # pragma: no cover - logging path isn't critical
            failures[channel] = exc
            logger.exception("Notifier %s failed", channel)

    if notifiers and len(failures) == len(notifiers):
        # Raise an exception so RQ retry semantics kick in when every channel fails.
        failures_str = ", ".join(f"{ch}: {err}" for ch, err in failures.items())
        raise RuntimeError(f"All notification channels failed: {failures_str}")


def notify_user(user_id: int, subject: str, body: str) -> None:
    """Enqueue a notification for asynchronous delivery."""

    queue.enqueue(_send_notification, user_id, subject, body, retry=Retry(max=3))


# ---------------------------------------------------------------------------
# Higher level helpers with simple templates
# ---------------------------------------------------------------------------

_TEMPLATES = {
    "approval_queue": (
        "Document {title} awaiting approval",
        "Document {title} is waiting for your approval.",
    ),
    "revision_time": (
        "Document {title} revised",
        "Document {title} has a new revision {major_version}.{minor_version}.",
    ),
    "mandatory_read": (
        "Document {title} requires your acknowledgement",
        "Please read and acknowledge document {title}.",
    ),
    "dif_step_overdue": (
        "DIF workflow step overdue",
        "A workflow step for DIF request {dif_id} assigned to {role} is overdue.",
    ),
}


def _render(template_key: str, **context: str) -> Tuple[str, str]:
    subject_t, body_t = _TEMPLATES[template_key]
    helper = EmailNotifier()  # Use prepare_message helper from base notifier
    return helper.prepare_message(subject_t, body_t, **context)


def notify_approval_queue(doc, user_ids):
    subject, body = _render("approval_queue", title=doc.title)
    for uid in user_ids:
        notify_user(uid, subject, body)


def notify_revision_time(doc, user_ids):
    subject, body = _render(
        "revision_time", title=doc.title, major_version=doc.major_version, minor_version=doc.minor_version
    )
    for uid in user_ids:
        notify_user(uid, subject, body)


def notify_mandatory_read(doc, user_ids):
    subject, body = _render("mandatory_read", title=doc.title)
    for uid in user_ids:
        notify_user(uid, subject, body)


def notify_dif_step_overdue(step, user_ids):
    subject, body = _render(
        "dif_step_overdue", dif_id=step.dif_id, role=step.role
    )
    for uid in user_ids:
        notify_user(uid, subject, body)

