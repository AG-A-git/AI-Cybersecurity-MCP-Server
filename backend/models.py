from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(
        String(100),
        unique=True,
        nullable=False
    )

    email = Column(
        String(200),
        unique=True,
        nullable=False
    )

    password_hash = Column(
        String(255),
        nullable=False
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )

    # One User → Many Projects
    projects = relationship(
        "Project",
        back_populates="owner",
        cascade="all, delete-orphan"
    )

    # One User → Many Uploaded Files
    uploaded_files = relationship(
        "UploadedFile",
        back_populates="user",
        cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    project_name = Column(
        String,
        nullable=False
    )

    description = Column(
        String,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    owner_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    # Project → User
    owner = relationship(
        "User",
        back_populates="projects"
    )

    # One Project → Many Uploaded Files
    uploaded_files = relationship(
        "UploadedFile",
        back_populates="project",
        cascade="all, delete-orphan"
    )
    
    # One Project → Many Scans
    scans = relationship(
        "Scan",
        back_populates="project",
        cascade="all, delete-orphan"
    )
    
class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    project_id = Column(
        Integer,
        ForeignKey("projects.id"),
        nullable=False
    )

    status = Column(
        String,
        nullable=False,
        default="pending"
    )

    started_at = Column(
        DateTime,
        nullable=True
    )

    completed_at = Column(
        DateTime,
        nullable=True
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )

    # Scan → Project
    project = relationship(
        "Project",
        back_populates="scans"
    )

    # One Scan → Many Vulnerabilities
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan"
    )


class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    filename = Column(
        String,
        nullable=False
    )

    filepath = Column(
        String,
        nullable=False
    )

    language = Column(
        String,
        nullable=False
    )

    upload_time = Column(
        DateTime,
        default=datetime.utcnow
    )

    project_id = Column(
        Integer,
        ForeignKey("projects.id"),
        nullable=False
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    # UploadedFile → Project
    project = relationship(
        "Project",
        back_populates="uploaded_files"
    )

    # UploadedFile → User
    user = relationship(
        "User",
        back_populates="uploaded_files"
    )
    
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False
    )

    file_name = Column(
        String,
        nullable=False
    )

    line_number = Column(
        Integer,
        nullable=True
    )

    vulnerability_type = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        nullable=False
    )

    confidence = Column(
        Integer,
        nullable=True
    )

    code = Column(
        String,
        nullable=True
    )

    # Vulnerability → Scan
    scan = relationship(
        "Scan",
        back_populates="vulnerabilities"
    )
    
