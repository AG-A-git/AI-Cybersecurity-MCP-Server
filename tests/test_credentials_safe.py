from scanner.scan import scan_file


def test_environment_credentials_not_detected():
    findings = scan_file("test_files/safe/credentials_safe.py")

    credential_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Hardcoded Credentials / Secrets"
    ]

    assert not credential_findings