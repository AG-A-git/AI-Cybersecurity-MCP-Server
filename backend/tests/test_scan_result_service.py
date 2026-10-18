from unittest.mock import MagicMock

from fastapi import HTTPException

from models import Project, Scan
from services.scan_result_service import get_owned_scan
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


def _mock_owned_scan_query(scan=None, project=None):
    """Mock sequential Scan and Project queries."""
    db = MagicMock()
    scan_query = MagicMock()
    project_query = MagicMock()

    scan_query.filter.return_value.first.return_value = scan
    project_query.filter.return_value.first.return_value = project

    db.query.side_effect = [scan_query, project_query]
    return db


def test_get_owned_scan_allows_project_owner():
    project = Project(id=10, project_name="Owned project", owner_id=7)
    scan = Scan(id=20, project_id=10, status="completed")
    db = _mock_owned_scan_query(scan=scan, project=project)

    result_scan, result_project = get_owned_scan(
        db,
        scan_id=20,
        user_id=7,
    )

    assert result_scan is scan
    assert result_project is project


def test_get_owned_scan_rejects_another_user():
    project = Project(id=10, project_name="Private project", owner_id=7)
    scan = Scan(id=20, project_id=10, status="completed")
    db = _mock_owned_scan_query(scan=scan, project=project)

    with pytest.raises(HTTPException) as exc_info:
        get_owned_scan(db, scan_id=20, user_id=99)

    assert exc_info.value.status_code == 403


def test_get_owned_scan_returns_404_for_missing_scan():
    db = _mock_owned_scan_query(scan=None)

    with pytest.raises(HTTPException) as exc_info:
        get_owned_scan(db, scan_id=999, user_id=7)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Scan not found"


def test_get_owned_scan_returns_404_for_missing_project():
    scan = Scan(id=20, project_id=10, status="completed")
    db = _mock_owned_scan_query(scan=scan, project=None)

    with pytest.raises(HTTPException) as exc_info:
        get_owned_scan(db, scan_id=20, user_id=7)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Project not found"
