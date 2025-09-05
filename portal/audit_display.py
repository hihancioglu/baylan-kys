from __future__ import annotations

from datetime import datetime
from typing import Mapping, Dict

from translations import get_locale

# Mapping of audit log actions to display metadata used in templates.
# Each entry maps an action name to an icon identifier and a translation key.
AUDIT_DISPLAY: Mapping[str, Dict[str, str]] = {
    "create": {"icon": "plus", "label_key": "audit_create"},
    "view": {"icon": "search", "label_key": "audit_view"},
    "download_document": {"icon": "download", "label_key": "audit_download_document"},
    "download_revision": {"icon": "download", "label_key": "audit_download_revision"},
    "version_uploaded": {"icon": "upload", "label_key": "audit_version_uploaded"},
    "publish_document": {"icon": "upload", "label_key": "audit_publish_document"},
    "assign_mr": {"icon": "bell", "label_key": "audit_assign_mr"},
    "checkout_document": {"icon": "download", "label_key": "audit_checkout_document"},
    "checkin_document": {"icon": "upload", "label_key": "audit_checkin_document"},
    "rollback": {"icon": "filter", "label_key": "audit_rollback"},
}


def inject_audit_display() -> dict[str, Mapping[str, Dict[str, str]]]:
    """Context processor that exposes ``AUDIT_DISPLAY`` to templates."""
    return {"audit_display": AUDIT_DISPLAY}


def format_dt(dt: datetime | None) -> str:
    """Return a locale-aware string representation of ``dt``.

    For Turkish locale (``tr``) the format ``dd.MM.yyyy HH:mm`` is used.  For
    any other locale, the timestamp is rendered in ISO format to minutes.
    ``None`` values yield an empty string.
    """
    if dt is None:
        return ""
    if get_locale() == "tr":
        return dt.strftime("%d.%m.%Y %H:%M")
    return dt.isoformat(sep=" ", timespec="minutes")

