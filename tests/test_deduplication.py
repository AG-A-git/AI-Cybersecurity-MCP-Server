from scanner.utils import deduplicate_findings


def make_finding(
    vulnerability_type="SQL Injection",
    file_name="test.py",
    line_number=25,
    confidence=90,
    code="query = user_input",
):
    return {
        "vulnerability_type": vulnerability_type,
        "file_name": file_name,
        "line_number": line_number,
        "severity": "High",
        "confidence": confidence,
        "code": code,
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


def test_different_code_on_same_line_is_preserved():
    finding_one = make_finding(
        code="query = user_input"
    )
    finding_two = make_finding(
        code="query = other_input"
    )

    result = deduplicate_findings(
        [finding_one, finding_two]
    )

    assert len(result) == 2

def test_selected_finding_preserves_evidence_and_optional_metadata():
    lower = {
        **make_finding(confidence=60),
        "evidence": {"source": "user_input"},
        "remediation": "Use parameterized queries",
    }
    higher = {
        **make_finding(confidence=90),
        "evidence": {"source": "request.args", "sink": "execute"},
        "remediation": "Use parameterized SQL queries",
    }

    result = deduplicate_findings([lower, higher])

    assert len(result) == 1
    assert result[0]["confidence"] == 90
    assert result[0]["evidence"] == higher["evidence"]
    assert result[0]["remediation"] == higher["remediation"]
    for field in (
        "vulnerability_type",
        "file_name",
        "line_number",
        "severity",
        "confidence",
        "evidence",
        "remediation",
    ):
        assert field in result[0]


def test_deduplication_is_stable_when_input_order_is_reversed():
    first = {
        **make_finding(confidence=80),
        "evidence": {"source": "source_a"},
    }
    second = {
        **make_finding(confidence=80),
        "evidence": {"source": "source_b"},
    }

    forward = deduplicate_findings([first, second])
    reverse = deduplicate_findings([second, first])

    assert forward == reverse


def test_deduplicating_twice_does_not_change_results():
    findings = [
        make_finding(confidence=70),
        make_finding(confidence=90),
        make_finding(line_number=30, confidence=80),
    ]

    once = deduplicate_findings(findings)
    twice = deduplicate_findings(once)

    assert twice == once

def test_equivalent_path_separators_are_deduplicated():
    forward_slashes = make_finding(file_name="src/app.py")
    backward_slashes = make_finding(file_name="src\\app.py")

    result = deduplicate_findings(
        [forward_slashes, backward_slashes]
    )

    assert len(result) == 1


def test_redundant_path_segments_are_deduplicated():
    normalized = make_finding(file_name="src/app.py")
    redundant_segments = make_finding(file_name="src/./app.py")

    result = deduplicate_findings(
        [normalized, redundant_segments]
    )

    assert len(result) == 1
