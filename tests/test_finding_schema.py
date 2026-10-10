import pytest
from scanner.finding import create_finding


def test_standard_finding_structure():
    finding = create_finding(
        vulnerability_type="SSRF",
        file_name="app.py",
        line_number=10,
        severity="High",
        confidence=85,
        code="requests.get(url)",
        owasp="A10: Server-Side Request Forgery",
        cwe="CWE-918"
    )

    required_fields = {
        "vulnerability_type",
        "file_name",
        "line_number",
        "severity",
        "confidence",
        "code",
    }

    assert required_fields.issubset(finding.keys())


def test_finding_line_number_is_integer():
    finding = create_finding(
        vulnerability_type="SQL Injection",
        file_name="app.py",
        line_number=15,
        severity="High",
        confidence=90,
        code="query = user_input",
        owasp="A03: Injection",
        cwe="CWE-89"
    )

    assert isinstance(
        finding["line_number"],
        int
    )


def test_finding_confidence_range():
    finding = create_finding(
        vulnerability_type="XSS",
        file_name="app.py",
        line_number=5,
        severity="High",
        confidence=90,
        code="return user_input",
        owasp="A03: Injection",
        cwe="CWE-79"
    )

    assert 0 <= finding["confidence"] <= 100


def test_finding_severity_is_valid():
    finding = create_finding(
        vulnerability_type="LDAP Injection",
        file_name="app.py",
        line_number=8,
        severity="High",
        confidence=85,
        code="ldap.search(query)",
        owasp="A03: Injection",
        cwe="CWE-90"
    )

    assert finding["severity"] in {
        "Critical",
        "High",
        "Medium",
        "Low",
    }


def test_invalid_confidence_is_rejected():
    try:
        create_finding(
            vulnerability_type="SSRF",
            file_name="app.py",
            line_number=10,
            severity="High",
            confidence=150,
            code="requests.get(url)",
            owasp="A10: Server-Side Request Forgery",
            cwe="CWE-918"
        )

        assert False

    except ValueError:
        assert True
def test_finding_fingerprint_is_deterministic():
    finding_one = create_finding(
        vulnerability_type="SSRF",
        file_name="app.py",
        line_number=10,
        severity="High",
        confidence=85,
        code="requests.get(url)",
        owasp="A10: Server-Side Request Forgery",
        cwe="CWE-918"
    )

    finding_two = create_finding(
        vulnerability_type="SSRF",
        file_name="app.py",
        line_number=10,
        severity="High",
        confidence=85,
        code="requests.get(url)",
        owasp="A10: Server-Side Request Forgery",
        cwe="CWE-918"
    )

    assert finding_one["fingerprint"] == finding_two["fingerprint"]
    assert len(finding_one["fingerprint"]) == 64


def test_finding_fingerprint_changes_for_different_line():
    finding_one = create_finding(
        vulnerability_type="SSRF",
        file_name="app.py",
        line_number=10,
        severity="High",
        confidence=85,
        code="requests.get(url)",
        owasp="A10: Server-Side Request Forgery",
        cwe="CWE-918"
    )

    finding_two = create_finding(
        vulnerability_type="SSRF",
        file_name="app.py",
        line_number=11,
        severity="High",
        confidence=85,
        code="requests.get(url)",
        owasp="A10: Server-Side Request Forgery",
        cwe="CWE-918"
    )

    assert finding_one["fingerprint"] != finding_two["fingerprint"]


def test_finding_fingerprint_ignores_confidence_and_evidence():
    finding_one = create_finding(
        vulnerability_type="SSRF",
        file_name="app.py",
        line_number=10,
        severity="High",
        confidence=85,
        code="requests.get(url)",
        owasp="A10: Server-Side Request Forgery",
        cwe="CWE-918"
    )

    finding_two = create_finding(
        vulnerability_type="SSRF",
        file_name="app.py",
        line_number=10,
        severity="High",
        confidence=60,
        code="requests.get(url)",
        owasp="A10: Server-Side Request Forgery",
        cwe="CWE-918",
        evidence={"source": "user_input"}
    )

    assert finding_one["fingerprint"] == finding_two["fingerprint"]

def test_boolean_line_number_is_rejected():
    with pytest.raises(ValueError):
        create_finding(
            vulnerability_type="SSRF",
            file_name="app.py",
            line_number=True,
            severity="High",
            confidence=85,
            code="requests.get(url)",
            owasp="A10: Server-Side Request Forgery",
            cwe="CWE-918",
        )

