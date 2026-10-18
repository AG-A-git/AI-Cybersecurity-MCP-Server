
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import services.mcp_server as mcp_server


@pytest.fixture
def report_setup(monkeypatch, tmp_path):
    db = Mock()
    report_data = {
        "id": 123,
        "project_id": 14,
        "project_name": "Report test",
        "status": "completed",
        "total_findings": 1,
        "vulnerability_count": 1,
        "severity_counts": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "risk_score": 82.5,
        "vulnerabilities": [
            {
                "file_name": "src/app.py",
                "line_number": 42,
                "vulnerability_type": "SQL Injection",
                "severity": "High",
                "risk_score": 82.5,
                "recommendation": "Use parameterized queries.",
            }
        ],
    }

    generator = Mock(return_value=report_data)
    file_metadata = {
        "file_name": "scan_123.json",
        "format": "json",
        "content_type": "application/json",
        "file_size_bytes": 512,
        "relative_path": "generated_reports/scan_123.json",
    }
    renderer = Mock(return_value=file_metadata)

    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )
    monkeypatch.setattr(mcp_server, "SessionLocal", lambda: db)
    monkeypatch.setattr(mcp_server, "generate_json_report", generator)
    monkeypatch.setattr(mcp_server, "generate_html_report", generator)
    monkeypatch.setattr(mcp_server, "generate_pdf_report", generator)
    monkeypatch.setattr(mcp_server, "render_report_file", renderer)

    return db, generator, renderer, report_data, file_metadata, tmp_path


@pytest.mark.parametrize("report_format", ["json", "html", "pdf"])
def test_generate_report_returns_generated_file_metadata(
    report_setup,
    report_format,
):
    db, generator, renderer, report_data, file_metadata, _ = report_setup

    result = mcp_server.generate_report(
        scan_id=123,
        report_format=report_format,
    )

    assert result["scan_id"] == 123
    assert result["format"] == report_format
    assert result["rendered_file"] is True
    assert result["report"] == report_data
    assert result["report"]["risk_score"] == 82.5
    assert result["report"]["vulnerabilities"][0]["recommendation"] == (
        "Use parameterized queries."
    )
    assert result["file"] == file_metadata

    generator.assert_called_once_with(db=db, scan_id=123, user_id=9)
    renderer.assert_called_once_with(
        report=report_data,
        scan_id=123,
        report_format=report_format,
    )
    db.close.assert_called_once()


def test_generate_report_normalizes_format(report_setup):
    db, generator, renderer, report_data, _, _ = report_setup

    result = mcp_server.generate_report(
        scan_id=123,
        report_format=" HTML ",
    )

    assert result["format"] == "html"
    assert result["report"] == report_data
    renderer.assert_called_once_with(
        report=report_data,
        scan_id=123,
        report_format="html",
    )
    generator.assert_called_once_with(db=db, scan_id=123, user_id=9)
    db.close.assert_called_once()


def test_generate_report_rejects_unsupported_format(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )

    with pytest.raises(ValueError, match="Unsupported report format"):
        mcp_server.generate_report(scan_id=123, report_format="docx")


def test_generate_report_rejects_non_string_format(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )

    with pytest.raises(ValueError, match="must be a string"):
        mcp_server.generate_report(scan_id=123, report_format=None)


def test_generate_report_closes_session_when_service_rejects_access(
    report_setup,
):
    db, generator, renderer, _, _, _ = report_setup
    generator.side_effect = mcp_server.HTTPException(
        status_code=403,
        detail="You do not have permission to access this scan",
    )

    with pytest.raises(mcp_server.ToolError, match="403"):
        mcp_server.generate_report(scan_id=123, report_format="json")

    renderer.assert_not_called()
    db.close.assert_called_once()


def test_generate_report_closes_session_on_database_error(report_setup):
    db, generator, renderer, _, _, _ = report_setup
    generator.side_effect = mcp_server.SQLAlchemyError(
        "simulated database failure"
    )

    with pytest.raises(ValueError, match="Unable to prepare the report"):
        mcp_server.generate_report(scan_id=123, report_format="json")

    renderer.assert_not_called()
    db.close.assert_called_once()


def test_generate_report_closes_session_on_file_write_error(report_setup):
    db, generator, renderer, _, _, _ = report_setup
    renderer.side_effect = OSError("simulated disk failure")

    with pytest.raises(ValueError, match="Unable to write the report file"):
        mcp_server.generate_report(scan_id=123, report_format="json")

    db.close.assert_called_once()

@pytest.mark.parametrize("invalid_scan_id", [0, -1, True])
def test_generate_report_rejects_invalid_scan_id(
    monkeypatch,
    invalid_scan_id,
):
    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )

    with pytest.raises(ValueError, match="scan_id must be a positive integer"):
        mcp_server.generate_report(
            scan_id=invalid_scan_id,
            report_format="json",
        )


def test_generate_report_handles_session_creation_failure(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )

    def fail_session_creation():
        raise mcp_server.SQLAlchemyError(
            "simulated session creation failure"
        )

    monkeypatch.setattr(
        mcp_server,
        "SessionLocal",
        fail_session_creation,
    )

    with pytest.raises(
        mcp_server.SQLAlchemyError,
        match="session creation failure",
    ):
        mcp_server.generate_report(
            scan_id=123,
            report_format="json",
        )
