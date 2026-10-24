import mcp_server
import pytest


def test_tracked_mcp_markdown_report_uses_canonical_finding_fields(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "get_scan",
        lambda **kwargs: {
            "project_path": "sample-project",
            "findings": [
                {
                    "vulnerability_type": "SQL Injection",
                    "severity": "High",
                    "file_name": "app.py",
                    "line_number": 12,
                    "confidence": 95,
                    "code": "cursor.execute(query)",
                }
            ],
        },
    )

    report = mcp_server.generate_report("unused.db", 1)

    assert report["found"] is True
    assert "### 1. SQL Injection" in report["content"]
    assert "- File: app.py" in report["content"]
    assert "- Line: 12" in report["content"]
    assert "- Severity: High" in report["content"]
