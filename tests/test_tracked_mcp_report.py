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


def test_legacy_finding_fields_are_normalized(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "get_scan",
        lambda **kwargs: {
            "project_path": "sample-project",
            "findings": [{
                "vulnerability": "SQL Injection",
                "severity": "High",
                "file": "app.py",
                "line": 0,
                "confidence": 95,
                "code": "cursor.execute(query)",
            }],
        },
    )

    report = mcp_server.generate_report("unused.db", 1)

    assert "### 1. SQL Injection" in report["content"]
    assert "- File: app.py" in report["content"]
    assert "- Line: 0" in report["content"]
    assert "- Severity: High" in report["content"]


def test_canonical_fields_take_precedence(monkeypatch):
    monkeypatch.setattr(
        mcp_server,
        "get_scan",
        lambda **kwargs: {
            "project_path": "sample-project",
            "findings": [{
                "vulnerability_type": "Canonical Type",
                "vulnerability": "Legacy Type",
                "file_name": "canonical.py",
                "file": "legacy.py",
                "line_number": 12,
                "line": 99,
                "severity": "High",
                "confidence": 95,
                "code": "cursor.execute(query)",
            }],
        },
    )

    report = mcp_server.generate_report("unused.db", 1, "json")
    import json
    finding = json.loads(report["content"])["findings"][0]

    assert finding["vulnerability_type"] == "Canonical Type"
    assert finding["file_name"] == "canonical.py"
    assert finding["line_number"] == 12
    assert finding["severity"] == "High"
    assert finding["confidence"] == 95
    assert finding["code"] == "cursor.execute(query)"
    assert finding["vulnerability"] == "Legacy Type"
    assert finding["file"] == "legacy.py"
    assert finding["line"] == 99
