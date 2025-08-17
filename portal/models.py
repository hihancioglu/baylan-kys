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
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
import sys

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///portal.db")

engine = create_engine(DATABASE_URL)
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()
sys.modules.setdefault("portal.models", sys.modules[__name__])


class RoleEnum(PyEnum):
    READER = "reader"
    CONTRIBUTOR = "contributor"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    PUBLISHER = "publisher"
    QUALITY_ADMIN = "quality_admin"
    AUDITOR = "auditor"


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    doc_key = Column(String, nullable=False, unique=True)
    title = Column(String, index=True)
    code = Column(String, index=True)
    tags = Column(String, index=True)
    department = Column(String, index=True)
    process = Column(String, index=True)
    major_version = Column(Integer, default=1)
    minor_version = Column(Integer, default=0)
    revision_notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    retention_period = Column(Integer)
    archived_at = Column(DateTime)

    status = Column(
        Enum("Draft", "Review", "Approved", "Published", "Archived", name="document_status"),
        default="Draft",
        nullable=False,
    )


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


class UserRole(Base):
    __tablename__ = "user_roles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)

    user = relationship("portal.models.User", back_populates="role_links")
    role = relationship("portal.models.Role", back_populates="user_links")
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    ldap_group = Column(String, unique=True)

    user_links = relationship(
        "portal.models.UserRole", back_populates="role", cascade="all, delete-orphan"
    )
    users = relationship(
        "User", secondary="user_roles", back_populates="roles"
    )
    permissions = relationship(
        "DocumentPermission", back_populates="role", cascade="all, delete-orphan"
    )


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True)

    role_links = relationship(
        "portal.models.UserRole", back_populates="user", cascade="all, delete-orphan"
    )
    roles = relationship(
        "Role", secondary="user_roles", back_populates="users"
    )
class DocumentPermission(Base):
    __tablename__ = "document_permissions"
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"))
    folder = Column(String)

    role = relationship("Role", back_populates="permissions")
    document = relationship("Document")


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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

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

# Database schema migrations are now managed via Alembic. Tables are created
# through explicit migration scripts rather than automatic metadata creation.

def get_session():
    return SessionLocal()


def seed_roles_and_users():
    """Seed default roles and test users."""
    session = get_session()
    try:
        for role in RoleEnum:
            if not session.query(Role).filter_by(name=role.value).first():
                session.add(Role(name=role.value))
        session.commit()
        for role in RoleEnum:
            username = f"test_{role.value}"
            user = session.query(User).filter_by(username=username).first()
            if not user:
                user = User(username=username, email=f"{username}@example.com")
                session.add(user)
                session.commit()
            role_obj = session.query(Role).filter_by(name=role.value).first()
            link = session.query(UserRole).filter_by(user_id=user.id, role_id=role_obj.id).first()
            if not link:
                session.add(UserRole(user_id=user.id, role_id=role_obj.id))
        session.commit()
    finally:
        session.close()

# Initial data seeding should be invoked manually after applying migrations.
