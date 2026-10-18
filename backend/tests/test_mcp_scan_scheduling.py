from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import services.mcp_server as mcp_server


def setup_scan_project(monkeypatch):
    db = Mock()
    scan = SimpleNamespace(
        id=123,
        project_id=14,
        status="pending",
    )
    executor = Mock()

    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )
    monkeypatch.setattr(
        mcp_server,
        "SessionLocal",
        lambda: db,
    )
    monkeypatch.setattr(
        mcp_server,
        "create_scan",
        Mock(return_value=scan),
    )
    monkeypatch.setattr(
        mcp_server,
        "_scan_executor",
        executor,
    )

    return db, scan, executor


def test_scan_project_submits_background_worker(monkeypatch):
    db, scan, executor = setup_scan_project(monkeypatch)

    result = mcp_server.scan_project(project_id=14)

    executor.submit.assert_called_once_with(
        mcp_server.execute_scan_in_background,
        scan.id,
        mcp_server.SessionLocal,
    )
    assert result["scan_id"] == scan.id
    assert result["project_id"] == scan.project_id
    assert result["status"] == "pending"
    db.close.assert_called_once()


def test_scan_project_marks_scan_failed_if_submission_fails(
    monkeypatch,
):
    db, scan, executor = setup_scan_project(monkeypatch)
    executor.submit.side_effect = RuntimeError("executor shut down")

    fail_scan = Mock()
    monkeypatch.setattr(
        mcp_server,
        "fail_scan_safely",
        fail_scan,
    )

    with pytest.raises(
        ValueError,
        match="Unable to schedule the scan",
    ):
        mcp_server.scan_project(project_id=14)

    fail_scan.assert_called_once_with(
        db,
        scan.id,
        "Scan could not be scheduled. Please retry.",
    )
    db.close.assert_called_once()