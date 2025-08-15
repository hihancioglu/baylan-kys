import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, JSON
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///portal.db")

engine = create_engine(DATABASE_URL)
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    doc_key = Column(String, nullable=False, unique=True)
    major_version = Column(Integer, default=1)
    minor_version = Column(Integer, default=0)
    revision_notes = Column(Text)

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

Base.metadata.create_all(engine)

def get_session():
    return SessionLocal()
