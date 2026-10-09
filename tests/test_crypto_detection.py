
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


def test_detects_md5_via_hashlib_new(tmp_path):
    from scanner.rules.crypto import scan_crypto

    file_path = tmp_path / "weak_hash.py"
    file_path.write_text(
        'import hashlib\n'
        'digest = hashlib.new("md5", b"example")\n',
        encoding="utf-8",
    )

    findings = scan_crypto(str(file_path))

    assert len(findings) == 1
    assert findings[0]["vulnerability_type"] == "Weak Cryptography"