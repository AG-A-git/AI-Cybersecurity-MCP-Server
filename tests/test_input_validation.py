from scanner.rules.input_validation import scan_input_validation


def test_sql_injection_from_user_input():
    findings = scan_input_validation(
        "scanner/test_files/input_validation_test.py"
    )

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings


def test_command_injection_from_user_input():
    findings = scan_input_validation(
        "scanner/test_files/input_validation_test.py"
    )

    command_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert command_findings


def test_standardized_fields():
    findings = scan_input_validation(
        "scanner/test_files/input_validation_test.py"
    )

    assert findings

    required_fields = {
        "vulnerability_type",
        "file_name",
        "line_number",
        "severity",
        "confidence",
        "code",
    }

    for finding in findings:
        assert required_fields.issubset(finding.keys())


def test_validation_reduces_sql_confidence():
    findings = scan_input_validation(
        "scanner/test_files/input_validation_safe_test.py"
    )

    sql_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "SQL Injection"
    ]

    assert sql_findings
    assert sql_findings[0]["confidence"] < 90


def test_validation_reduces_command_confidence():
    findings = scan_input_validation(
        "scanner/test_files/input_validation_safe_test.py"
    )

    command_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Command Injection"
    ]

    assert command_findings
    assert command_findings[0]["confidence"] < 90


def test_xss_from_user_input():
    findings = scan_input_validation(
        "scanner/test_files/xss_input_validation_test.js"
    )

    xss_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"]
        == "Cross-Site Scripting (XSS)"
    ]

    assert xss_findings


def test_safe_text_content_not_detected_as_xss():
    findings = scan_input_validation(
        "scanner/test_files/xss_safe_input_test.js"
    )

    xss_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"]
        == "Cross-Site Scripting (XSS)"
    ]

    assert not xss_findings