from scanner.scan import scan_file


def test_sha256_not_detected_as_weak_cryptography():
    findings = scan_file("test_files/safe/crypto_safe.py")

    crypto_findings = [
        finding
        for finding in findings
        if finding["vulnerability_type"] == "Weak Cryptography"
    ]

    assert not crypto_findings