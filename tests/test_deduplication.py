from scanner.utils import deduplicate_findings


def make_finding(
    vulnerability_type="SQL Injection",
    file_name="test.py",
    line_number=25,
    confidence=90,
):
    return {
        "vulnerability_type": vulnerability_type,
        "file_name": file_name,
        "line_number": line_number,
        "severity": "High",
        "confidence": confidence,
        "code": "query = user_input",
    }


def test_duplicate_findings_removed():
    findings = [
        make_finding(confidence=70),
        make_finding(confidence=90),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 1
    assert result[0]["confidence"] == 90


def test_different_lines_are_preserved():
    findings = [
        make_finding(line_number=25),
        make_finding(line_number=30),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 2


def test_different_vulnerabilities_are_preserved():
    findings = [
        make_finding(
            vulnerability_type="SQL Injection"
        ),
        make_finding(
            vulnerability_type="Cross-Site Scripting (XSS)"
        ),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 2


def test_different_files_are_preserved():
    findings = [
        make_finding(file_name="test.py"),
        make_finding(file_name="app.py"),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 2


def test_highest_confidence_is_kept():
    findings = [
        make_finding(confidence=70),
        make_finding(confidence=90),
        make_finding(confidence=80),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 1
    assert result[0]["confidence"] == 90