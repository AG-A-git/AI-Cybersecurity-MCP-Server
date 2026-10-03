import pytest

from models import Scan, Vulnerability
from services.scan_result_service import (
    calculate_scan_risk_score,
    calculate_severity_counts,
    validate_scan_summary,
    serialize_vulnerability,
)


def test_calculate_scan_risk_score_returns_highest_risk():
    scan = Scan()

    vulnerability_1 = Vulnerability(
        risk_score=35.0
    )

    vulnerability_2 = Vulnerability(
        risk_score=82.5
    )

    vulnerability_3 = Vulnerability(
        risk_score=60.0
    )

    scan.vulnerabilities = [
        vulnerability_1,
        vulnerability_2,
        vulnerability_3,
    ]

    assert calculate_scan_risk_score(scan) == 82.5


def test_calculate_scan_risk_score_returns_zero_for_no_findings():
    scan = Scan()

    scan.vulnerabilities = []

    assert calculate_scan_risk_score(scan) == 0


def test_calculate_severity_counts():
    vulnerabilities = [
        Vulnerability(severity="Critical"),
        Vulnerability(severity="Critical"),
        Vulnerability(severity="High"),
        Vulnerability(severity="Medium"),
        Vulnerability(severity="Low"),
        Vulnerability(severity="Info"),
    ]

    counts = calculate_severity_counts(vulnerabilities)

    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["info"] == 1


def test_validate_scan_summary_accepts_matching_counts():
    severity_counts = {
        "critical": 2,
        "high": 1,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    validate_scan_summary(
        total_findings=6,
        severity_counts=severity_counts,
    )


def test_validate_scan_summary_rejects_mismatched_counts():
    severity_counts = {
        "critical": 2,
        "high": 1,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    with pytest.raises(
        ValueError,
        match="Scan summary severity counts do not match total findings",
    ):
        validate_scan_summary(
            total_findings=10,
            severity_counts=severity_counts,
        )


def test_serialize_vulnerability_preserves_core_fields():
    vulnerability = Vulnerability(
        id=1,
        file_name="app.py",
        line_number=25,
        vulnerability_type="SQL Injection",
        severity="High",
        confidence=90,
        code="cursor.execute(query)",
        risk_score=81.0,
        owasp_category="A03:2021",
        cwe_id="CWE-89",
        explanation="User input reaches a database query.",
        impact="An attacker may manipulate the SQL query.",
        recommendation="Use parameterized queries.",
    )

    result = serialize_vulnerability(vulnerability)

    assert result["id"] == 1
    assert result["file_name"] == "app.py"
    assert result["line_number"] == 25
    assert result["vulnerability_type"] == "SQL Injection"
    assert result["severity"] == "High"
    assert result["confidence"] == 90
    assert result["code"] == "cursor.execute(query)"
    assert result["risk_score"] == 81.0
    assert result["owasp_category"] == "A03:2021"
    assert result["cwe_id"] == "CWE-89"
    assert result["explanation"] == "User input reaches a database query."
    assert result["impact"] == "An attacker may manipulate the SQL query."
    assert result["recommendation"] == "Use parameterized queries."