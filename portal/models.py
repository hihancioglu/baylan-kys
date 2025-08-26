import os
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    ForeignKey,
    DateTime,
    JSON,
    Enum,
    UniqueConstraint,
    Boolean,
    Float,
    Table,
)
from sqlalchemy.orm import (
    declarative_base,
    relationship,
    sessionmaker,
    scoped_session,
    joinedload,
    synonym,
)
import sys

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///portal.db")

engine = create_engine(DATABASE_URL)
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()
sys.modules["portal.models"] = sys.modules[__name__]


def _parse_standard_map(raw: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in raw.split(","):
        if ":" not in item:
            continue
        code, name = item.split(":", 1)
        code = code.strip()
        name = name.strip()
        if code:
            mapping[code] = name or code
    return mapping


STANDARD_MAP = _parse_standard_map(
    os.environ.get(
        "ISO_STANDARDS",
        "ISO9001:ISO 9001,ISO27001:ISO 27001,ISO14001:ISO 14001",
    )
)


class RoleEnum(PyEnum):
    READER = "reader"
    CONTRIBUTOR = "contributor"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    PUBLISHER = "publisher"
    QUALITY_ADMIN = "quality_admin"
    AUDITOR = "auditor"
    SURVEY_ADMIN = "survey_admin"
    COMPLAINTS_OWNER = "complaints_owner"
    RISK_COMMITTEE = "risk_committee"


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    file_key = Column(String, nullable=False, unique=True)
    doc_key = synonym("file_key")
    title = Column(String, index=True)
    code = Column(String, index=True)
    rev_no = Column(Integer, default=0)
    standard_code = Column(String, index=True, nullable=True)
    tags = Column(String, index=True)
    department = Column(String, index=True)
    process = Column(String, index=True)
    major_version = Column(Integer, default=1)
    minor_version = Column(Integer, default=0)
    revision_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    mime = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    retention_period = Column(Integer)
    archived_at = Column(DateTime)

    status = Column(
        Enum("Draft", "Review", "Approved", "Published", "Archived", name="document_status"),
        default="Draft",
        nullable=False,
    )

    owner = relationship("User", foreign_keys=[owner_id])


class DocumentRevision(Base):
    __tablename__ = "document_revisions"
    id = Column(Integer, primary_key=True)
    doc_id = Column(Integer, ForeignKey('documents.id'), nullable=False)
    major_version = Column(Integer, nullable=False)
    minor_version = Column(Integer, nullable=False)
    revision_notes = Column(Text)
    track_changes = Column(JSON)
    compare_result = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

    document = relationship(Document, back_populates="revisions")


class DocumentPermission(Base):
    __tablename__ = "document_permissions"
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"))
    folder = Column(String)
    can_download = Column(Boolean, default=True)

    role = relationship("Role", back_populates="permissions")
    document = relationship("Document")


class Standard(Base):
    __tablename__ = "standards"
    code = Column(String, primary_key=True)
    description = Column(String)

    documents = relationship(
        "DocumentStandard", back_populates="standard", cascade="all, delete-orphan"
    )


class DocumentStandard(Base):
    __tablename__ = "document_standards"
    doc_id = Column(Integer, ForeignKey("documents.id"), primary_key=True)
    standard_code = Column(String, ForeignKey("standards.code"), primary_key=True)

    document = relationship("Document", back_populates="standards")
    standard = relationship("Standard", back_populates="documents")


user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", ForeignKey("users.id"), nullable=False),
    Column("role_id", ForeignKey("roles.id"), nullable=False),
    UniqueConstraint("user_id", "role_id", name="uq_user_role"),
)


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    ldap_group = Column(String, unique=True)
    standard_scope = Column(String, nullable=False, default="ALL")
    users = relationship(
        "User", secondary=user_roles, back_populates="roles"
    )
    permissions = relationship(
        DocumentPermission, back_populates="role", cascade="all, delete-orphan"
    )


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True)
    roles = relationship(
        Role, secondary=user_roles, back_populates="users"
    )


class WorkflowStep(Base):
    __tablename__ = "workflow_steps"
    id = Column(Integer, primary_key=True)
    doc_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    step_order = Column(Integer, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    step_type = Column(
        Enum("review", "approval", name="workflow_step_type"),
        default="review",
        nullable=False,
    )
    status = Column(String, default="Pending", nullable=False)
    approved_at = Column(DateTime)
    comment = Column(Text)

    document = relationship(Document, back_populates="workflow_steps")
    user = relationship(User)


class Acknowledgement(Base):
    __tablename__ = "acknowledgements"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)

    user = relationship("User")
    document = relationship("Document")
    __table_args__ = (
        UniqueConstraint("user_id", "doc_id", name="uq_acknowledgement"),
    )


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    read = Column(Boolean, default=False, nullable=False)

    user = relationship("User")


class TrainingResult(Base):
    __tablename__ = "training_results"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    score = Column(Integer, default=0)
    max_score = Column(Integer, default=0)
    incorrect = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)
    passed = Column(Boolean, default=False)
    completed_at = Column(DateTime, default=datetime.utcnow)
    ack_id = Column(Integer, ForeignKey("acknowledgements.id"))

    user = relationship("User")
    acknowledgement = relationship("Acknowledgement")


class FormSubmission(Base):
    __tablename__ = "form_submissions"
    id = Column(Integer, primary_key=True)
    form_name = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    data = Column(JSON)
    submitted_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class ChangeRequest(Base):
    __tablename__ = "change_requests"
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    document = relationship("Document")


class Deviation(Base):
    __tablename__ = "deviations"
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    document = relationship("Document")


class CAPAAction(Base):
    __tablename__ = "capa_actions"
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    action = Column(Text)
    status = Column(
        Enum("Open", "In Progress", "Closed", name="capa_status"),
        default="Open",
        nullable=False,
    )
    created_at = Column(DateTime, default=datetime.utcnow)

    document = relationship("Document")


class UserSetting(Base):
    __tablename__ = "user_settings"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    language = Column(String, default="en")
    theme = Column(String, default="light")
    email_enabled = Column(Boolean, default=True)
    webhook_enabled = Column(Boolean, default=False)
    webhook_url = Column(String)

    user = relationship("User")


class SignatureLog(Base):
    __tablename__ = "signature_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    signed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")
    document = relationship("Document")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"))
    action = Column(String, nullable=False)
    endpoint = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    timestamp = synonym("created_at")

    user = relationship("User")
    document = relationship("Document")


class PersonalAccessToken(Base):
    __tablename__ = "personal_access_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String)
    token_hash = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")


class DepartmentVisibility(Base):
    """Visibility flags for departments."""
    __tablename__ = "department_visibility"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    visible = Column(Boolean, default=True, nullable=False)

# establish relationships defined after class declarations
Document.workflow_steps = relationship(
    WorkflowStep, back_populates="document", cascade="all, delete-orphan"
)
Document.revisions = relationship(
    DocumentRevision, back_populates="document", cascade="all, delete-orphan"
)
Document.standards = relationship(
    DocumentStandard, back_populates="document", cascade="all, delete-orphan"
)

# Database schema migrations are now managed via Alembic. Tables are created
# through explicit migration scripts rather than automatic metadata creation.

def get_session():
    return SessionLocal()


def get_document(doc_id: int):
    """Fetch a document with its revision history."""
    session = get_session()
    try:
        return (
            session.query(Document)
            .options(joinedload(Document.revisions))
            .filter(Document.id == doc_id)
            .one_or_none()
        )
    finally:
        session.close()


def seed_roles_and_users():
    """Seed default roles and test users."""
    session = get_session()
    try:
        for role in RoleEnum:
            if not session.query(Role).filter_by(name=role.value).first():
                session.add(Role(name=role.value, standard_scope="ALL"))
        session.commit()
        for role in RoleEnum:
            username = f"test_{role.value}"
            user = session.query(User).filter_by(username=username).first()
            if not user:
                user = User(username=username, email=f"{username}@example.com")
                session.add(user)
                session.commit()
            role_obj = session.query(Role).filter_by(name=role.value).first()
            if role_obj not in user.roles:
                user.roles.append(role_obj)
        session.commit()
    finally:
        session.close()

def seed_documents():
    """Seed sample documents demonstrating standard usage."""
    session = get_session()
    try:
        if session.query(Document).count() == 0:
            codes = list(STANDARD_MAP.keys())
            if not codes:
                return
            first = codes[0]
            second = codes[1] if len(codes) > 1 else first
            third = codes[2] if len(codes) > 2 else (second if len(codes) > 1 else first)

            doc1 = Document(
                doc_key="seed_doc1.docx",
                title="Seeded Document 1",
                code="SD1",
                standard_code=first,
                standards=[DocumentStandard(standard_code=first)],
            )
            doc2 = Document(
                doc_key="seed_doc2.docx",
                title="Seeded Document 2",
                code="SD2",
                standard_code=first,
                standards=[
                    DocumentStandard(standard_code=first),
                    DocumentStandard(standard_code=second),
                ],
            )
            doc3 = Document(
                doc_key="seed_doc3.docx",
                title="Seeded Document 3",
                code="SD3",
                standard_code=third,
                standards=[DocumentStandard(standard_code=third)],
            )
            session.add_all([doc1, doc2, doc3])
            session.commit()
    finally:
        session.close()

# Initial data seeding should be invoked manually after applying migrations.

__all__ = [
    "Base",
    "SessionLocal",
    "get_session",
    "seed_roles_and_users",
    "seed_documents",
    "RoleEnum",
    "Document",
    "DocumentRevision",
    "DocumentPermission",
    "Standard",
    "DocumentStandard",
    "Role",
    "User",
    "WorkflowStep",
    "Acknowledgement",
    "Notification",
    "TrainingResult",
    "FormSubmission",
    "SignatureLog",
    "AuditLog",
    "PersonalAccessToken",
    "DepartmentVisibility",
]
