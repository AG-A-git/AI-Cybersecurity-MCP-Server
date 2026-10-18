from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import services.mcp_server as mcp_server


@pytest.fixture
def report_setup(monkeypatch):
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

    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )
    monkeypatch.setattr(mcp_server, "SessionLocal", lambda: db)
    monkeypatch.setattr(
        mcp_server,
        "generate_json_report",
        generator,
    )
    monkeypatch.setattr(
        mcp_server,
        "generate_html_report",
        generator,
    )
    monkeypatch.setattr(
        mcp_server,
        "generate_pdf_report",
        generator,
    )

    return db, generator, report_data


@pytest.mark.parametrize(
    "report_format",
    ["json", "html", "pdf"],
)
def test_generate_report_returns_prepared_data_not_rendered_file(
    report_setup,
    report_format,
):
    db, generator, report_data = report_setup

    result = mcp_server.generate_report(
        scan_id=123,
        report_format=report_format,
    )

    assert result["scan_id"] == 123
    assert result["format"] == report_format
    assert result["rendered_file"] is False
    assert result["report"] == report_data
    assert result["report"]["risk_score"] == 82.5
    assert result["report"]["vulnerabilities"][0]["recommendation"] == (
        "Use parameterized queries."
    )
    generator.assert_called_once_with(
        db=db,
        scan_id=123,
        user_id=9,
    )
    db.close.assert_called_once()


def test_generate_report_normalizes_format(report_setup):
    db, generator, report_data = report_setup

    result = mcp_server.generate_report(
        scan_id=123,
        report_format=" HTML ",
    )

    assert result["format"] == "html"
    assert result["report"] == report_data
    generator.assert_called_once_with(
        db=db,
        scan_id=123,
        user_id=9,
    )
    db.close.assert_called_once()


def test_generate_report_rejects_unsupported_format(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "get_authenticated_mcp_user",
        lambda: SimpleNamespace(user_id=9),
    )

    with pytest.raises(
        ValueError,
        match="Unsupported report format",
    ):
        mcp_server.generate_report(
            scan_id=123,
            report_format="docx",
        )


def test_generate_report_closes_session_when_service_rejects_access(
    report_setup,
):
    db, generator, _ = report_setup
    generator.side_effect = mcp_server.HTTPException(
        status_code=403,
        detail="You do not have permission to access this scan",
    )

    with pytest.raises(
        mcp_server.ToolError,
        match="403",
    ):
        mcp_server.generate_report(
            scan_id=123,
            report_format="json",
        )

    db.close.assert_called_once()


def test_generate_report_closes_session_on_database_error(
    report_setup,
):
    db, generator, _ = report_setup
    generator.side_effect = mcp_server.SQLAlchemyError(
        "simulated database failure"
    )

    with pytest.raises(
        ValueError,
        match="Unable to prepare the report",
    ):
        mcp_server.generate_report(
            scan_id=123,
            report_format="json",
        )

    db.close.assert_called_once()
