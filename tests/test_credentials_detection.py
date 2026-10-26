
from scanner.scan import scan_file


def test_hardcoded_credentials_detected():
    findings = scan_file("tests/credentials_test.py")

    credential_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Hardcoded Credentials / Secrets"
    ]

    assert credential_findings


def test_hardcoded_credentials_have_standard_fields():
    findings = scan_file("tests/credentials_test.py")

    credential_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Hardcoded Credentials / Secrets"
    ]

    assert credential_findings

    required_fields = {
        "file_name",
        "line_number",
        "vulnerability_type",
        "severity",
        "confidence",
        "code",
    }

    for finding in credential_findings:
        assert required_fields.issubset(finding.keys())


def test_detects_hardcoded_secret_in_dictionary(tmp_path):
    from scanner.rules.credentials import scan_credentials

    file_path = tmp_path / "settings.py"
    file_path.write_text(
        'config = {"api_key": "sk_live_123456"}\n',
        encoding="utf-8",
    )

    findings = scan_credentials(str(file_path))

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == (
        "Hardcoded Credentials / Secrets"
    )