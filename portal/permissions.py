from models import get_session, User, Document, DocumentPermission


def permission_check(user, document, download: bool = False) -> bool:
    """Return True if the given user has access to the document.

    The function checks both document-specific and folder-level permissions
    based on the roles assigned to the user. If ``download`` is set to ``True``
    the permission must also explicitly allow downloading.

    Parameters
    ----------
    user: User | int
        User object or user id.
    document: Document | int
        Document object or document id.
    download: bool
        Require download permission in addition to access.
    """
    session = get_session()
    try:
        if isinstance(user, int):
            db_user = session.get(User, user)
        else:
            db_user = session.get(User, user.id)
        if isinstance(document, int):
            doc = session.get(Document, document)
        else:
            doc = session.get(Document, document.id)
        if not db_user or not doc:
            return False
        role_ids = [role.id for role in db_user.roles]
        if not role_ids:
            return False
        perms = (
            session.query(DocumentPermission)
            .filter(DocumentPermission.role_id.in_(role_ids))
            .all()
        )
        for perm in perms:
            if perm.doc_id and perm.doc_id == doc.id:
                if download and not perm.can_download:
                    continue
                return True
            if perm.folder and doc.doc_key.startswith(perm.folder):
                if download and not perm.can_download:
                    continue
                return True
        return False
    finally:
        session.close()
