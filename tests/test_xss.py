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

def test_xss_detects_multi_hop_user_input(tmp_path):
    test_file = tmp_path / "xss_multi_hop.py"

    test_file.write_text(
        """user_input = request.args.get("message")
value = user_input
final_value = value

element.innerHTML = final_value
""",
        encoding="utf-8",
    )

    findings = scan_xss(str(test_file))

    xss_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Cross-Site Scripting (XSS)"
    ]

    assert xss_findings
    assert xss_findings[0]["confidence"] == 80

def test_xss_does_not_flag_unrelated_data_variable(tmp_path):
    test_file = tmp_path / "xss_safe_data.py"

    test_file.write_text(
        """data = "safe content"
element.innerHTML = data
""",
        encoding="utf-8",
    )

    findings = scan_xss(str(test_file))

    xss_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Cross-Site Scripting (XSS)"
    ]

    assert not xss_findings


def test_xss_detects_request_input_with_generic_variable_name(tmp_path):
    test_file = tmp_path / "xss_generic_variable.py"
    test_file.write_text(
        '''data = request.args.get("message")
element.innerHTML = data
''',
        encoding="utf-8",
    )

    findings = scan_xss(str(test_file))

    xss_findings = [
        finding for finding in findings
        if finding["vulnerability_type"] == "Cross-Site Scripting (XSS)"
    ]

    assert xss_findings
