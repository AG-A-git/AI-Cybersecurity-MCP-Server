from scanner.finding import validate_finding
from scanner.scan import scan_file
from scanner.utils import deduplicate_findings


def test_central_scanner_reports_correct_sql_source_location(tmp_path):
    source = (
        'from flask import request\n'
        'username = request.args.get("username")\n'
        'query = "SELECT * FROM users WHERE name=\'" + username\n'
    )
    test_file = tmp_path / "task8_sql_location.py"
    test_file.write_text(source, encoding="utf-8")

    findings = scan_file(test_file)
    sql_findings = [
        finding for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings, "Expected SQL injection finding"

    finding = sql_findings[0]
    source_lines = source.splitlines()

    assert finding["file_name"] == str(test_file)
    assert finding["line_number"] == 3
    assert finding["code"] == source_lines[2].strip()
    assert source_lines[finding["line_number"] - 1].strip() == finding["code"]


def test_all_central_scanner_findings_pass_schema_validation(tmp_path):
    test_file = tmp_path / "task8_multiple_findings.py"
    test_file.write_text(
        'from flask import request\n'
        'import requests\n'
        'username = request.args.get("username")\n'
        'query = "SELECT * FROM users WHERE name=\'" + username\n'
        'requests.get(username)\n',
        encoding="utf-8",
    )

    findings = scan_file(test_file)

    assert findings, "Expected at least one finding"
    for finding in findings:
        assert validate_finding(finding) is finding
        assert finding["file_name"] == str(test_file)
        assert isinstance(finding["line_number"], int)
        assert finding["line_number"] > 0
        assert 0 <= finding["confidence"] <= 100


def test_duplicate_findings_keep_highest_confidence():
    low_confidence = {
        "vulnerability_type": "SQL Injection",
        "file_name": "app.py",
        "line_number": 4,
        "code": "query = user_input",
        "confidence": 60,
        "severity": "Medium",
    }
    high_confidence = {
        **low_confidence,
        "confidence": 90,
        "severity": "High",
    }

    result = deduplicate_findings([low_confidence, high_confidence])

    assert len(result) == 1
    assert result[0]["confidence"] == 90
    assert result[0]["severity"] == "High"


def test_equal_confidence_duplicate_keeps_more_severe_finding():
    medium = {
        "vulnerability_type": "SQL Injection",
        "file_name": "app.py",
        "line_number": 4,
        "code": "query = user_input",
        "confidence": 85,
        "severity": "Medium",
    }
    critical = {**medium, "severity": "Critical"}

    for findings in ([medium, critical], [critical, medium]):
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "Critical"
