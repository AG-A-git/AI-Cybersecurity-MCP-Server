import pytest

from services.scan_service import (
    normalize_scanner_finding,
    validate_finding,
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
        match="Finding risk score must be an integer"
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