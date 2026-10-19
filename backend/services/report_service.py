
"""Prepare and render reports for scans owned by authenticated users."""

import html
import json
import re
from pathlib import Path
from typing import Any

from fpdf import FPDF
from sqlalchemy.orm import Session

from logging_config import get_logger
from services.scan_result_service import get_scan_result

logger = get_logger(__name__)

REPORT_DIR = Path(__file__).resolve().parents[1] / "generated_reports"

REPORT_FORMATS = {
    "json": ("application/json", ".json"),
    "html": ("text/html; charset=utf-8", ".html"),
    "pdf": ("application/pdf", ".pdf"),
}


def get_report_data(db: Session, scan_id: int, user_id: int):
    """Return normalized scan data after checking scan ownership."""
    logger.info(
        "Report data requested | scan_id=%s | user_id=%s",
        scan_id,
        user_id,
    )
    return get_scan_result(db=db, scan_id=scan_id, user_id=user_id)


def generate_json_report(db: Session, scan_id: int, user_id: int):
    """Prepare JSON report data; file rendering is handled separately."""
    logger.info("JSON report requested | scan_id=%s | user_id=%s", scan_id, user_id)
    return get_report_data(db=db, scan_id=scan_id, user_id=user_id)


def generate_html_report(db: Session, scan_id: int, user_id: int):
    """Prepare HTML report data; file rendering is handled separately."""
    logger.info("HTML report requested | scan_id=%s | user_id=%s", scan_id, user_id)
    return get_report_data(db=db, scan_id=scan_id, user_id=user_id)


def generate_pdf_report(db: Session, scan_id: int, user_id: int):
    """Prepare PDF report data; file rendering is handled separately."""
    logger.info("PDF report requested | scan_id=%s | user_id=%s", scan_id, user_id)
    return get_report_data(db=db, scan_id=scan_id, user_id=user_id)


def _as_text(value: Any) -> str:
    """Convert arbitrary report values to text safe for built-in PDF fonts."""
    return str(value if value is not None else "").encode(
        "latin-1", errors="replace"
    ).decode("latin-1")


def _render_html(report: dict[str, Any]) -> str:
    """Render report content with HTML escaping for untrusted scan findings."""
    vulnerabilities = report.get("vulnerabilities", []) or []
    finding_rows = []

    for finding in vulnerabilities:
        finding = finding if isinstance(finding, dict) else {}
        recommendation = finding.get("recommendation")
        if not isinstance(recommendation, str) or not recommendation.strip():
            recommendation = "No recommendation available."
        finding_rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('severity', 'Unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('vulnerability_type', 'Unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('file_name', 'Unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('line_number', 'Unknown')))}</td>"
            f"<td><pre>{html.escape(str(finding.get('code', '')))}</pre></td>"
            f"<td>{html.escape(recommendation)}</td>"
            "</tr>"
        )

    if not finding_rows:
        finding_rows.append(
            '<tr><td colspan="6">No vulnerabilities recorded for this scan.</td></tr>'
        )

    scan_id = html.escape(str(report.get("id", report.get("scan_id", ""))))
    project = html.escape(str(report.get("project_name", "Unknown")))
    status = html.escape(str(report.get("status", "Unknown")))
    risk = html.escape(str(report.get("risk_score", 0)))
    total = html.escape(
        str(report.get("total_findings", report.get("vulnerability_count", 0)))
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan Report - {scan_id}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 2rem; color: #172033; }}
h1 {{ color: #12315b; }}
.summary {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
.summary p {{ padding: .75rem; background: #eef3f9; border-radius: .4rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1.5rem; }}
th, td {{ border: 1px solid #ccd4df; padding: .65rem; text-align: left; vertical-align: top; }}
th {{ background: #12315b; color: white; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }}
</style>
</head>
<body>
<h1>Security Scan Report</h1>
<div class="summary">
<p><strong>Scan ID:</strong> {scan_id}</p>
<p><strong>Project:</strong> {project}</p>
<p><strong>Status:</strong> {status}</p>
<p><strong>Total findings:</strong> {total}</p>
<p><strong>Risk score:</strong> {risk}</p>
</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Vulnerability</th><th>File</th>
<th>Line</th><th>Code evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(finding_rows)}</tbody>
</table>
</body>
</html>
"""


def _render_pdf(report: dict[str, Any]) -> bytes:
    """Render a readable PDF using FPDF's built-in font."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_title(
        f"Security Scan Report {report.get('id', report.get('scan_id', ''))}"
    )

    def paragraph(text: Any, height: float = 7) -> None:
        # Explicit width and starting position prevent zero-width layout errors.
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(
            w=pdf.epw,
            h=height,
            text=_as_text(text),
        )

    pdf.set_font("Helvetica", style="B", size=18)
    paragraph("Security Scan Report", 12)

    pdf.set_font("Helvetica", size=11)
    summary_fields = (
        ("Scan ID", report.get("id", report.get("scan_id", ""))),
        ("Project", report.get("project_name", "Unknown")),
        ("Status", report.get("status", "Unknown")),
        (
            "Total findings",
            report.get("total_findings", report.get("vulnerability_count", 0)),
        ),
        ("Risk score", report.get("risk_score", 0)),
    )

    for label, value in summary_fields:
        paragraph(f"{label}: {value}")

    pdf.ln(4)
    pdf.set_font("Helvetica", style="B", size=14)
    paragraph("Findings", 9)

    vulnerabilities = report.get("vulnerabilities", []) or []
    pdf.set_font("Helvetica", size=10)

    if not vulnerabilities:
        paragraph("No vulnerabilities recorded for this scan.")

    for index, finding in enumerate(vulnerabilities, start=1):
        finding = finding if isinstance(finding, dict) else {}

        pdf.set_font("Helvetica", style="B", size=11)
        paragraph(
            f"{index}. {finding.get('severity', 'Unknown')} - "
            f"{finding.get('vulnerability_type', 'Unknown')}"
        )

        pdf.set_font("Helvetica", size=10)
        for label, key in (
            ("File", "file_name"),
            ("Line", "line_number"),
            ("Code", "code"),
            ("Recommendation", "recommendation"),
        ):
            value = finding.get(key, "")
            if key == "recommendation" and (
                not isinstance(value, str) or not value.strip()
            ):
                value = "No recommendation available."
            if value not in (None, ""):
                paragraph(f"{label}: {value}", 6)

        pdf.ln(3)

    return bytes(pdf.output())


def render_report_file(
    report: dict[str, Any],
    scan_id: int,
    report_format: str,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Write a report file and return safe metadata, not the absolute path."""
    normalized_format = report_format.strip().lower() if isinstance(report_format, str) else ""
    if normalized_format not in REPORT_FORMATS:
        raise ValueError("Unsupported report format. Choose json, html, or pdf.")

    if not isinstance(scan_id, int) or isinstance(scan_id, bool) or scan_id < 1:
        raise ValueError("scan_id must be a positive integer.")
    if not isinstance(report, dict):
        raise ValueError("Report data must be an object.")

    content_type, extension = REPORT_FORMATS[normalized_format]
    directory = Path(output_dir) if output_dir is not None else REPORT_DIR
    directory.mkdir(parents=True, exist_ok=True)

    # The filename uses only a validated integer and a fixed extension.
    file_name = f"scan_{scan_id}.{extension.lstrip('.')}"
    output_path = directory / file_name

    if normalized_format == "json":
        content = json.dumps(report, indent=2, ensure_ascii=False, default=str).encode("utf-8")
    elif normalized_format == "html":
        content = _render_html(report).encode("utf-8")
    else:
        content = _render_pdf(report)

    output_path.write_bytes(content)

    logger.info(
        "Report file generated | scan_id=%s | format=%s | bytes=%s",
        scan_id,
        normalized_format,
        len(content),
    )
    return {
        "file_name": file_name,
        "format": normalized_format,
        "content_type": content_type,
        "file_size_bytes": len(content),
        "relative_path": f"generated_reports/{file_name}",
   }
