from scanner.scan import scan_file


def test_weak_cryptography_detected():
    findings = scan_file("tests/crypto_test.py")

    crypto_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Weak Cryptography"
    ]

    assert crypto_findings


def test_weak_cryptography_has_standard_fields():
    findings = scan_file("tests/crypto_test.py")

    crypto_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Weak Cryptography"
    ]

    assert crypto_findings

    required_fields = {
        "file_name",
        "line_number",
        "vulnerability_type",
        "severity",
        "confidence",
        "code",
    }

    for finding in crypto_findings:
        assert required_fields.issubset(finding.keys())