
import pytest
from pydantic import ValidationError

from ai.input import validate_vulnerability
from ai.mapping import get_mapping
from scanner.engine import scan_project


@pytest.fixture
def valid_finding():
    return {
        "file": "app.py",
        "line": 25,
        "vulnerability": "SQLi",
        "severity": "High",
        "confidence": 90,
        "code": "query = user_input",
    }


@pytest.mark.parametrize("data", [None, [], "not a finding"])
def test_rejects_invalid_top_level_input(data):
    with pytest.raises((TypeError, ValidationError)):
        validate_vulnerability(data)


def test_rejects_empty_finding(valid_finding):
    with pytest.raises(ValidationError):
        validate_vulnerability({})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file", 123),
        ("vulnerability", ["SQLi"]),
        ("severity", ["High"]),
        ("code", ["query = user_input"]),
        ("line", []),
    ],
)
def test_rejects_invalid_field_types(valid_finding, field, value):
    valid_finding[field] = value

    with pytest.raises(ValidationError):
        validate_vulnerability(valid_finding)


@pytest.mark.parametrize("file_value", ["", "   "])
def test_rejects_empty_or_whitespace_file(valid_finding, file_value):
    valid_finding["file"] = file_value

    with pytest.raises(ValidationError):
        validate_vulnerability(valid_finding)


@pytest.mark.parametrize("line", [0, -1])
def test_rejects_non_positive_line(valid_finding, line):
    valid_finding["line"] = line

    with pytest.raises(ValidationError):
        validate_vulnerability(valid_finding)


@pytest.mark.parametrize(
    "severity",
    ["", "   ", "Unclassified"],
)
def test_rejects_empty_or_unsupported_severity(
    valid_finding, severity
):
    valid_finding["severity"] = severity

    with pytest.raises(ValidationError):
        validate_vulnerability(valid_finding)


def test_accepts_supported_severity_case_variants(valid_finding):
    valid_finding["severity"] = "HIGH"

    result = validate_vulnerability(valid_finding)

    assert result.severity == "HIGH"


def test_accepts_very_long_source_code(valid_finding):
    long_code = "x = 1\n" * 50_000
    valid_finding["code"] = long_code

    result = validate_vulnerability(valid_finding)

    assert result.code == long_code


def test_accepts_finding_without_owasp_or_cwe_metadata(valid_finding):
    result = validate_vulnerability(valid_finding)

    assert result.file == "app.py"
    assert result.code == "query = user_input"


def test_eval_scanner_finding_normalizes_and_maps_code_injection(
    tmp_path,
):
    source_file = tmp_path / "sample.py"
    source_file.write_text(
        "eval(user_input)\n",
        encoding="utf-8",
    )

    findings = scan_project(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["vulnerability"] == "Code Injection"

    normalized = validate_vulnerability(findings[0])

    assert normalized.vulnerability == "Code Injection"
    assert get_mapping(normalized.vulnerability) == {
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-94",
    }
