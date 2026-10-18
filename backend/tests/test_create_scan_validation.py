import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import User, Project, UploadedFile, Scan
from services.scan_service import create_scan


@pytest.fixture
def db(tmp_path):
    database_path = tmp_path / "create_scan_validation.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def create_user(db, username):
    user = User(
        username=username,
        email=f"{username}@example.test",
        password_hash="test-hash",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_project(db, owner_id, name="Test Project"):
    project = Project(
        project_name=name,
        description="Validation test project",
        owner_id=owner_id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def add_uploaded_file(db, project_id, user_id):
    uploaded_file = UploadedFile(
        filename="sample.py",
        filepath="/tmp/sample.py",
        language="python",
        project_id=project_id,
        user_id=user_id,
    )
    db.add(uploaded_file)
    db.commit()
    return uploaded_file


def test_create_scan_rejects_missing_project(db):
    user = create_user(db, "missing_project_user")

    with pytest.raises(HTTPException) as exc:
        create_scan(db, project_id=999999, user_id=user.id)

    assert exc.value.status_code == 404
    assert exc.value.detail == "Project not found"


def test_create_scan_rejects_project_owned_by_another_user(db):
    owner = create_user(db, "project_owner")
    other_user = create_user(db, "other_user")
    project = create_project(db, owner.id)
    add_uploaded_file(db, project.id, owner.id)

    with pytest.raises(HTTPException) as exc:
        create_scan(db, project_id=project.id, user_id=other_user.id)

    assert exc.value.status_code == 403
    assert exc.value.detail == (
        "You do not have permission to scan this project"
    )


def test_create_scan_rejects_project_without_uploaded_files(db):
    user = create_user(db, "no_files_user")
    project = create_project(db, user.id)

    with pytest.raises(HTTPException) as exc:
        create_scan(db, project_id=project.id, user_id=user.id)

    assert exc.value.status_code == 400
    assert exc.value.detail == (
        "No uploaded files found for this project"
    )


def test_create_scan_rejects_existing_active_scan(db):
    user = create_user(db, "active_scan_user")
    project = create_project(db, user.id)
    add_uploaded_file(db, project.id, user.id)

    existing_scan = Scan(
        project_id=project.id,
        status="pending",
    )
    db.add(existing_scan)
    db.commit()

    with pytest.raises(HTTPException) as exc:
        create_scan(db, project_id=project.id, user_id=user.id)

    assert exc.value.status_code == 409
    assert exc.value.detail == (
        "A scan is already in progress for this project"
    )


def test_create_scan_accepts_valid_request(db):
    user = create_user(db, "valid_scan_user")
    project = create_project(db, user.id)
    add_uploaded_file(db, project.id, user.id)

    scan = create_scan(db, project_id=project.id, user_id=user.id)

    assert scan.id is not None
    assert scan.project_id == project.id
    assert scan.status == "pending"
