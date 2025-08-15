import os
from datetime import datetime
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
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///portal.db")

engine = create_engine(DATABASE_URL)
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

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

    workflow_steps = relationship(
        "WorkflowStep", back_populates="document", cascade="all, delete-orphan"
    )

    revisions = relationship("DocumentRevision", back_populates="document", cascade="all, delete-orphan")

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

    document = relationship("Document", back_populates="revisions")


class WorkflowStep(Base):
    __tablename__ = "workflow_steps"
    id = Column(Integer, primary_key=True)
    doc_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    step_order = Column(Integer, nullable=False)
    approver = Column(String)
    status = Column(String, default="Pending", nullable=False)
    approved_at = Column(DateTime)

    document = relationship("Document", back_populates="workflow_steps")


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    ldap_group = Column(String, unique=True)

    users = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    permissions = relationship("DocumentPermission", back_populates="role", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True)

    roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")


class UserRole(Base):
    __tablename__ = "user_roles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)


class DocumentPermission(Base):
    __tablename__ = "document_permissions"
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"))
    folder = Column(String)

    role = relationship("Role", back_populates="permissions")
    document = relationship("Document")


class Acknowledgement(Base):
    __tablename__ = "acknowledgements"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    acknowledged_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")
    document = relationship("Document")
    __table_args__ = (
        UniqueConstraint("user_id", "doc_id", name="uq_acknowledgement"),
    )


class TrainingResult(Base):
    __tablename__ = "training_results"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    score = Column(Integer, default=0)
    max_score = Column(Integer, default=0)
    passed = Column(Boolean, default=False)
    completed_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


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


class NotificationSetting(Base):
    __tablename__ = "notification_settings"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    email_enabled = Column(Boolean, default=True)
    webhook_enabled = Column(Boolean, default=False)
    webhook_url = Column(String)

    user = relationship("User")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doc_id = Column(Integer, ForeignKey("documents.id"))
    action = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")
    document = relationship("Document")

Base.metadata.create_all(engine)

def get_session():
    return SessionLocal()
