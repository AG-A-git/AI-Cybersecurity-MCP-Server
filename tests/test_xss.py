from scanner.rules.xss import scan_xss


def test_xss_vulnerable_and_source_context():
    findings = scan_xss(
        "scanner/test_files/xss_accuracy_test.js"
    )

    xss_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Cross-Site Scripting (XSS)"
    ]

    assert len(xss_findings) == 2

    for finding in xss_findings:
        assert "source_context" in finding
        assert finding["source_context"]["start_line"] <= finding["line_number"]
        assert finding["source_context"]["end_line"] >= finding["line_number"]
        assert finding["source_context"]["lines"]


def test_xss_safe_literals_not_detected():
    findings = scan_xss(
        "scanner/test_files/xss_accuracy_test.js"
    )

    xss_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Cross-Site Scripting (XSS)"
    ]

    finding_lines = {
        finding["line_number"]
        for finding in xss_findings
    }

    assert 2 not in finding_lines
    assert 4 not in finding_lines
