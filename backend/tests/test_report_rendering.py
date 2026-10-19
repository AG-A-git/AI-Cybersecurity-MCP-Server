
import json

import pytest

from services.report_service import render_report_file


@pytest.fixture
def report_data():
    return {
        "id": 25,
        "project_name": "Report Rendering Test",
        "status": "completed",
        "total_findings": 1,
        "risk_score": 85.5,
        "vulnerabilities": [
            {
                "file_name": "src/app.py",
                "line_number": 12,
                "vulnerability_type": "SQL Injection",
                "severity": "Critical",
                "code": "query = '<script>alert(1)</script>'",
                "recommendation": "Use parameterized queries.",
            }
        ],
    }


@pytest.mark.parametrize(
    ("report_format", "extension", "content_type"),
    [
        ("json", ".json", "application/json"),
        ("html", ".html", "text/html; charset=utf-8"),
        ("pdf", ".pdf", "application/pdf"),
    ],
)
def test_render_report_creates_nonempty_file(
    tmp_path,
    report_data,
    report_format,
    extension,
    content_type,
):
    result = render_report_file(
        report=report_data,
        scan_id=25,
        report_format=report_format,
        output_dir=tmp_path,
    )

    generated_file = tmp_path / f"scan_25{extension}"

    assert generated_file.is_file()
    assert generated_file.stat().st_size > 0
    assert result["file_name"] == generated_file.name
    assert result["format"] == report_format
    assert result["content_type"] == content_type
    assert result["file_size_bytes"] == generated_file.stat().st_size
    assert result["relative_path"] == f"generated_reports/{generated_file.name}"
    assert "file_path" not in result


def test_json_report_contains_scan_and_finding_data(tmp_path, report_data):
    render_report_file(report_data, 25, "json", output_dir=tmp_path)

    generated = json.loads((tmp_path / "scan_25.json").read_text(encoding="utf-8"))

    assert generated["id"] == 25
    assert generated["risk_score"] == 85.5
    assert generated["vulnerabilities"][0]["line_number"] == 12
    assert generated["vulnerabilities"][0]["severity"] == "Critical"


def test_html_report_escapes_untrusted_finding_content(tmp_path, report_data):
    render_report_file(report_data, 25, "html", output_dir=tmp_path)

    generated = (tmp_path / "scan_25.html").read_text(encoding="utf-8")

    assert "SQL Injection" in generated
    assert "Use parameterized queries." in generated
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in generated
    assert "<script>alert(1)</script>" not in generated


def test_pdf_report_has_pdf_signature(tmp_path, report_data):
    render_report_file(report_data, 25, "pdf", output_dir=tmp_path)

    generated = (tmp_path / "scan_25.pdf").read_bytes()

    assert generated.startswith(b"%PDF-")
    assert b"%%EOF" in generated[-1024:]


@pytest.mark.parametrize(
    ("scan_id", "report_format"),
    [
        (0, "json"),
        (-1, "html"),
        (True, "pdf"),
        (25, "docx"),
    ],
)
def test_renderer_rejects_invalid_arguments(
    tmp_path,
    report_data,
    scan_id,
    report_format,
):
    with pytest.raises(ValueError):
        render_report_file(
            report=report_data,
            scan_id=scan_id,
            report_format=report_format,
            output_dir=tmp_path,
        )


def test_renderer_rejects_non_object_report(tmp_path):
    with pytest.raises(ValueError, match="Report data must be an object"):
        render_report_file(
            report=[],
            scan_id=25,
            report_format="json",
            output_dir=tmp_path,
        )
@pytest.mark.parametrize("report_format", ["html", "pdf"])
def test_missing_recommendation_is_explicit(
    tmp_path, report_data, report_format
):
    report_data["vulnerabilities"][0]["recommendation"] = None

    render_report_file(
        report=report_data,
        scan_id=25,
        report_format=report_format,
        output_dir=tmp_path,
    )

    generated = tmp_path / f"scan_25.{report_format}"

    assert generated.is_file()
    assert generated.stat().st_size > 0

    if report_format == "html":
        content = generated.read_text(encoding="utf-8")
        assert "No recommendation available." in content