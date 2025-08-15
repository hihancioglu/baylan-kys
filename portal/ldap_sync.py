"""Simple LDAP sync module.

The module connects to an LDAP server and synchronises the group names with the
`roles` table. Each LDAP group becomes a role if it does not already exist.
"""

import os
from typing import List
from urllib.parse import urlparse

import ldap3
from models import get_session, Role

LDAP_URL = os.environ.get("LDAP_URL", "ldap://localhost")
LDAP_USER = os.environ.get("LDAP_USER")
LDAP_PASSWORD = os.environ.get("LDAP_PASSWORD")
LDAP_GROUP_BASE = os.environ.get("LDAP_GROUP_BASE", "ou=groups,dc=example,dc=com")

# Parse the URL to support ldaps:// and custom ports
_url = urlparse(LDAP_URL)
_USE_SSL = _url.scheme == "ldaps"
_PORT = _url.port or (636 if _USE_SSL else 389)
_HOST = _url.hostname or LDAP_URL


def fetch_groups() -> List[str]:
    """Fetch group names from LDAP."""
    server = ldap3.Server(_HOST, port=_PORT, use_ssl=_USE_SSL, get_info=ldap3.NONE)
    try:
        conn = ldap3.Connection(server, user=LDAP_USER, password=LDAP_PASSWORD, auto_bind=True)
        conn.search(LDAP_GROUP_BASE, "(objectClass=group)", attributes=["cn"])
        groups = [entry.cn.value for entry in conn.entries]
        conn.unbind()
        return groups
    except Exception:
        # In case LDAP is unreachable return empty list; log in real implementation
        return []


def sync_roles_from_ldap() -> None:
    """Synchronise LDAP groups with the roles table."""
    session = get_session()
    try:
        for name in fetch_groups():
            role = session.query(Role).filter_by(ldap_group=name).first()
            if not role:
                session.add(Role(name=name, ldap_group=name))
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    sync_roles_from_ldap()
