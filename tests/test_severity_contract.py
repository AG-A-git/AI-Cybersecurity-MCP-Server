import pytest

from scanner.finding import validate_finding
from scanner.severity import get_severity


@pytest.mark.parametrize(
    ("vulnerability", "expected"),
    [
        ("SQL Injection", "Critical"),
        ("Command Injection", "Critical"),
        ("Cross-Site Scripting", "High"),
        ("Hardcoded Credentials", "High"),
        ("Path Traversal", "High"),
        ("Weak Cryptography", "Medium"),
        ("Insecure Deserialization", "Medium"),
        ("Information Disclosure", "Low"),
        ("Debug Code", "Low"),
        ("Code Style", "Info"),
        ("Unused Variable", "Info"),
    ],
)
def test_known_vulnerability_severity_mapping(vulnerability, expected):
    assert get_severity(vulnerability) == expected


@pytest.mark.parametrize(
    "vulnerability",
    ["Unknown Vulnerability", "", None],
)
def test_unknown_vulnerability_type_is_rejected(vulnerability):
    with pytest.raises(ValueError, match="Unknown vulnerability type"):
        get_severity(vulnerability)


def test_standardized_finding_rejects_informational_severity():
    finding = {
        "file_name": "example.py",
        "line_number": 1,
        "vulnerability_type": "Code Style",
        "severity": "Info",
        "confidence": 90,
        "code": "unused_variable = 1",
    }

    with pytest.raises(ValueError, match="Invalid severity"):
        validate_finding(finding)


def test_standardized_finding_accepts_valid_security_severity():
    finding = {
        "file_name": "example.py",
        "line_number": 1,
        "vulnerability_type": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }

    assert validate_finding(finding) is finding
