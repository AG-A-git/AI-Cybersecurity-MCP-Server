import pytest

from services.scan_service import (
    normalize_scanner_finding,
    validate_finding,
    finding_identity,
    deduplicate_findings,
)


def test_normalize_scanner_finding():
    finding = {
        "file": "  test.py  ",
        "line": 12,
        "vulnerability": "  SQL Injection  ",
        "severity": "high",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }

    normalized = normalize_scanner_finding(
        finding
    )

    assert normalized == {
        "file": "test.py",
        "line": 12,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }


def test_validate_valid_finding():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "risk_score": 90,
        "code": "query",
    }

    validate_finding(
        finding
    )


def test_validate_float_risk_score():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 75,
        "risk_score": 56.25,
    }

    validate_finding(
        finding
    )


def test_validate_missing_file():
    finding = {
        "file": None,
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
    }

    with pytest.raises(
        ValueError,
        match="Finding file is required"
    ):
        validate_finding(
            finding
        )


def test_validate_invalid_line():
    finding = {
        "file": "test.py",
        "line": 0,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
    }

    with pytest.raises(
        ValueError,
        match="Finding line must be a positive integer"
    ):
        validate_finding(
            finding
        )


def test_validate_invalid_confidence():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 101,
    }

    with pytest.raises(
        ValueError,
        match="Finding confidence must be between 0 and 100"
    ):
        validate_finding(
            finding
        )


def test_validate_invalid_risk_score():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "risk_score": 101,
    }

    with pytest.raises(
        ValueError,
        match="Finding risk score must be between 0 and 100"
    ):
        validate_finding(
            finding
        )


def test_validate_boolean_risk_score():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "risk_score": True,
    }

    with pytest.raises(
        ValueError,
        match="Finding risk score must be numeric"
    ):
        validate_finding(
            finding
        )


def test_validate_string_risk_score():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "risk_score": "90",
    }

    with pytest.raises(
        ValueError,
        match="Finding risk score must be numeric"
    ):
        validate_finding(
            finding
        )


def test_validate_invalid_severity():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Extreme",
    }

    with pytest.raises(
        ValueError,
        match="Unsupported finding severity"
    ):
        validate_finding(
            finding
        )


def test_validate_boolean_confidence():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": True,
    }

    with pytest.raises(
        ValueError,
        match="Finding confidence must be an integer"
    ):
        validate_finding(
            finding
        )


def test_validate_boolean_line():
    finding = {
        "file": "test.py",
        "line": True,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
    }

    with pytest.raises(
        ValueError,
        match="Finding line must be a positive integer"
    ):
        validate_finding(
            finding
        )


def test_finding_identity():
    finding = {
        "file": "test.py",
        "line": 10,
        "vulnerability": "SQL Injection",
    }

    assert finding_identity(
        finding
    ) == (
        "test.py",
        10,
        "SQL Injection",
    )


def test_duplicate_findings_are_removed():
    findings = [
        {
            "file": "test.py",
            "line": 10,
            "vulnerability": "SQL Injection",
            "severity": "High",
        },
        {
            "file": "test.py",
            "line": 10,
            "vulnerability": "SQL Injection",
            "severity": "High",
        },
        {
            "file": "app.py",
            "line": 20,
            "vulnerability": "XSS",
            "severity": "Medium",
        },
    ]

    unique_findings = deduplicate_findings(
        findings
    )

    assert len(unique_findings) == 2

    assert unique_findings[0] == findings[0]
    assert unique_findings[1] == findings[2]


def test_findings_with_different_lines_are_not_duplicates():
    findings = [
        {
            "file": "test.py",
            "line": 10,
            "vulnerability": "SQL Injection",
        },
        {
            "file": "test.py",
            "line": 20,
            "vulnerability": "SQL Injection",
        },
    ]

    unique_findings = deduplicate_findings(
        findings
    )

    assert len(unique_findings) == 2


def test_findings_with_different_vulnerabilities_are_not_duplicates():
    findings = [
        {
            "file": "test.py",
            "line": 10,
            "vulnerability": "SQL Injection",
        },
        {
            "file": "test.py",
            "line": 10,
            "vulnerability": "XSS",
        },
    ]

    unique_findings = deduplicate_findings(
        findings
    )

    assert len(unique_findings) == 2

def test_ai_enriched_finding_preserves_scanner_and_ai_fields():
    scanner_finding = {
        "file": "security_test.py",
        "line": 42,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": "cursor.execute(query)",
    }

    normalized = normalize_scanner_finding(scanner_finding)

    ai_enriched = {
        **normalized,
        "risk_score": 81.0,
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "explanation": "User-controlled input reaches a SQL query.",
        "impact": "An attacker may manipulate the database query.",
        "recommendation": "Use parameterized queries.",
    }

    validate_finding(ai_enriched)

    assert ai_enriched["file"] == "security_test.py"
    assert ai_enriched["line"] == 42
    assert ai_enriched["vulnerability"] == "SQL Injection"
    assert ai_enriched["severity"] == "High"
    assert ai_enriched["confidence"] == 90
    assert ai_enriched["code"] == "cursor.execute(query)"

    assert ai_enriched["risk_score"] == 81.0
    assert ai_enriched["owasp"] == "A03:2021"
    assert ai_enriched["cwe"] == "CWE-89"
    assert ai_enriched["explanation"] == (
        "User-controlled input reaches a SQL query."
    )
    assert ai_enriched["impact"] == (
        "An attacker may manipulate the database query."
    )
    assert ai_enriched["recommendation"] == (
        "Use parameterized queries."
    )
