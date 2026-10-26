from pathlib import Path

from scanner.rules.sql import scan_sql
from scanner.finding import validate_finding


def test_sql_findings_include_structured_evidence(tmp_path):
    source = (
        'from flask import request\n'
        'username = request.args.get("username")\n'
        'query = "SELECT * FROM users WHERE name=\'" + username\n'
    )
    test_file = tmp_path / "sql_evidence.py"
    test_file.write_text(source, encoding="utf-8")

    findings = scan_sql(str(test_file))
    sql_findings = [
        finding for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings, "Expected a SQL injection finding"

    for finding in sql_findings:
        assert validate_finding(finding) is finding
        evidence = finding.get("evidence")
        assert isinstance(evidence, dict) and evidence
        assert evidence.get("sink") or evidence.get("reason")
        if "sink_line" in evidence:
            assert isinstance(evidence["sink_line"], int)
            assert evidence["sink_line"] > 0


def test_findings_without_evidence_remain_schema_valid():
    # Evidence is optional in the current finding schema.
    finding = {
        "file_name": "example.py",
        "line_number": 1,
        "vulnerability_type": "Weak Cryptography",
        "severity": "High",
        "confidence": 90,
        "code": "hashlib.md5(data)",
    }

    assert validate_finding(finding) is finding
