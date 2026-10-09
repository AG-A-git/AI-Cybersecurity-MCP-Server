
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import User, Project, Scan, UploadedFile
from services import scan_worker


@pytest.fixture
def worker_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    user = User(
        username="worker_test_user",
        email="worker_test@example.com",
        password_hash="test-hash",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    project = Project(
        project_name="Worker Test Project",
        description="Test background scan execution",
        owner_id=user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    try:
        yield db, TestingSessionLocal, project.id, user.id
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def add_scan(db, project_id, status="pending"):
    scan = Scan(project_id=project_id, status=status)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def add_uploaded_file(db, project_id, user_id):
    uploaded_file = UploadedFile(
        filename="sample.py",
        filepath="tests/sample_upload.py",
        language="python",
        project_id=project_id,
        user_id=user_id,
    )
    db.add(uploaded_file)
    db.commit()
    db.refresh(uploaded_file)
    return uploaded_file


def test_missing_scan_is_handled(worker_db, caplog):
    _, session_factory, _, _ = worker_db

    scan_worker.execute_scan_in_background(
        scan_id=999999,
        session_factory=session_factory,
    )

    assert "Background scan not found" in caplog.text


def test_non_pending_scan_is_skipped(
    worker_db,
    monkeypatch,
    caplog,
):
    db, session_factory, project_id, _ = worker_db
    scan = add_scan(db, project_id, status="completed")

    def unexpected_pipeline(*args, **kwargs):
        pytest.fail("Pipeline must not run for a completed scan")

    monkeypatch.setattr(
        scan_worker,
        "run_scan_pipeline",
        unexpected_pipeline,
    )

    scan_worker.execute_scan_in_background(
        scan.id,
        session_factory,
    )

    db.expire_all()
    saved_scan = db.query(Scan).filter(Scan.id == scan.id).one()

    assert saved_scan.status == "completed"
    assert "Skipping scan" in caplog.text


def test_pending_scan_without_files_fails(worker_db):
    db, session_factory, project_id, _ = worker_db
    scan = add_scan(db, project_id)

    scan_worker.execute_scan_in_background(
        scan.id,
        session_factory,
    )

    db.expire_all()
    saved_scan = db.query(Scan).filter(Scan.id == scan.id).one()

    assert saved_scan.status == "failed"
    assert saved_scan.completed_at is not None
    assert "No uploaded files" in saved_scan.error_message


def test_pending_scan_completes_successfully(
    worker_db,
    monkeypatch,
):
    db, session_factory, project_id, user_id = worker_db
    scan = add_scan(db, project_id)
    add_uploaded_file(db, project_id, user_id)

    def fake_pipeline(db_session, scan_record, uploaded_files):
        assert db_session is not db
        assert scan_record.status == "running"
        assert len(uploaded_files) == 1
        return []

    monkeypatch.setattr(
        scan_worker,
        "run_scan_pipeline",
        fake_pipeline,
    )

    scan_worker.execute_scan_in_background(
        scan.id,
        session_factory,
    )

    db.expire_all()
    saved_scan = db.query(Scan).filter(Scan.id == scan.id).one()

    assert saved_scan.status == "completed"
    assert saved_scan.started_at is not None
    assert saved_scan.completed_at is not None
    assert saved_scan.error_message is None


def test_pipeline_failure_marks_scan_failed(
    worker_db,
    monkeypatch,
):
    db, session_factory, project_id, user_id = worker_db
    scan = add_scan(db, project_id)
    add_uploaded_file(db, project_id, user_id)

    def failing_pipeline(*args, **kwargs):
        raise RuntimeError("Simulated scanner failure")

    monkeypatch.setattr(
        scan_worker,
        "run_scan_pipeline",
        failing_pipeline,
    )

    scan_worker.execute_scan_in_background(
        scan.id,
        session_factory,
    )

    db.expire_all()
    saved_scan = db.query(Scan).filter(Scan.id == scan.id).one()

    assert saved_scan.status == "failed"
    assert saved_scan.completed_at is not None
    assert "Scan execution failed" in saved_scan.error_message


def test_worker_closes_database_session(worker_db):
    _, session_factory, _, _ = worker_db
    created_sessions = []
    close_calls = []

    def tracking_session_factory():
        session = session_factory()
        original_close = session.close

        def tracked_close(*args, **kwargs):
            close_calls.append(True)
            return original_close(*args, **kwargs)

        session.close = tracked_close
        created_sessions.append(session)
        return session

    scan_worker.execute_scan_in_background(
        scan_id=999999,
        session_factory=tracking_session_factory,
    )

    assert len(created_sessions) == 1
    assert close_calls == [True]


def test_pipeline_failure_rolls_back_and_persists_failed_status(
    worker_db,
    monkeypatch,
):
    db, session_factory, project_id, user_id = worker_db
    scan = add_scan(db, project_id)
    add_uploaded_file(db, project_id, user_id)

    def failing_pipeline(db_session, scan_record, uploaded_files):
        # Simulate uncommitted database work before the failure.
        db_session.add(
            Vulnerability(
                scan_id=scan_record.id,
                file_name="partial.py",
                vulnerability_type="Test finding",
                severity="High",
            )
        )
        raise RuntimeError("Simulated pipeline failure")

    from models import Vulnerability

    monkeypatch.setattr(
        scan_worker,
        "run_scan_pipeline",
        failing_pipeline,
    )

    scan_worker.execute_scan_in_background(
        scan.id,
        session_factory,
    )

    db.expire_all()
    saved_scan = db.query(Scan).filter(Scan.id == scan.id).one()
    saved_findings = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .all()
    )

    assert saved_scan.status == "failed"
    assert saved_scan.completed_at is not None
    assert "Scan execution failed" in saved_scan.error_message
    assert saved_findings == []


def test_worker_can_complete_another_scan_after_failure(
    worker_db,
    monkeypatch,
):
    db, session_factory, project_id, user_id = worker_db

    failed_scan = add_scan(db, project_id)
    add_uploaded_file(db, project_id, user_id)

    def failing_pipeline(*args, **kwargs):
        raise RuntimeError("First scan fails")

    monkeypatch.setattr(
        scan_worker,
        "run_scan_pipeline",
        failing_pipeline,
    )

    scan_worker.execute_scan_in_background(
        failed_scan.id,
        session_factory,
    )

    db.expire_all()
    saved_failed_scan = (
        db.query(Scan)
        .filter(Scan.id == failed_scan.id)
        .one()
    )
    assert saved_failed_scan.status == "failed"

    # A failed scan is no longer active, so a new scan can be created.
    successful_scan = add_scan(db, project_id)

    def successful_pipeline(*args, **kwargs):
        return []

    monkeypatch.setattr(
        scan_worker,
        "run_scan_pipeline",
        successful_pipeline,
    )

    scan_worker.execute_scan_in_background(
        successful_scan.id,
        session_factory,
    )

    db.expire_all()
    saved_successful_scan = (
        db.query(Scan)
        .filter(Scan.id == successful_scan.id)
        .one()
    )

    assert saved_successful_scan.status == "completed"
    assert saved_successful_scan.started_at is not None
    assert saved_successful_scan.completed_at is not None
    assert saved_successful_scan.error_message is None
