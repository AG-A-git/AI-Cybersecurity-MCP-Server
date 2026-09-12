from scanner.scan import scan_file


def test_central_scanner_detects_sql():
    findings = scan_file("test_files/vulnerable/sql_vulnerable.py")

    assert findings
    assert any(
        finding["vulnerability_type"] == "SQL Injection"
        for finding in findings
    )


def test_central_scanner_safe_file():
    findings = scan_file("test_files/safe/sql_safe.py")

    assert findings == []


def test_findings_have_standard_schema():
    findings = scan_file("test_files/vulnerable/sql_vulnerable.py")

    required_fields = {
        "file_name",
        "line_number",
        "vulnerability_type",
        "severity",
        "confidence",
        "code",
        "owasp",
        "cwe",
    }

    for finding in findings:
        assert required_fields.issubset(finding.keys())


def test_findings_are_sorted():
    findings = scan_file("test_files/vulnerable/sql_vulnerable.py")

    keys = [
        (
            finding["file_name"],
            finding["line_number"],
            finding["vulnerability_type"],
        )
        for finding in findings
    ]

    assert keys == sorted(keys)