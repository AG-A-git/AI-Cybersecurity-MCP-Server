import re

from scanner.finding import create_finding


CRYPTO_PATTERNS = [
    (
        re.compile(
            r'\bhashlib\.md5\s*\(',
            re.IGNORECASE
        ),
        "High",
        95
    ),
    (
        re.compile(
            r'\bhashlib\.sha1\s*\(',
            re.IGNORECASE
        ),
        "High",
        95
    ),
    (
        re.compile(
            r'\bDES(?:\.new)?\s*\(',
            re.IGNORECASE
        ),
        "High",
        95
    ),
    (
        re.compile(
            r'\b(?:ARC4|RC4)(?:\.new)?\s*\(',
            re.IGNORECASE
        ),
        "High",
        95
    ),
]


def scan_crypto(file_path):
    """
    Detect weak or deprecated cryptographic algorithms.
    """

    results = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            lines = file.readlines()

    except (FileNotFoundError, OSError):
        return results

    for line_number, line in enumerate(lines, start=1):

        for pattern, severity, confidence in CRYPTO_PATTERNS:

            if pattern.search(line):

                results.append(
                    create_finding(
                        file_name=file_path,
                        line_number=line_number,
                        vulnerability_type="Weak Cryptography",
                        severity=severity,
                        confidence=confidence,
                        code=line.strip(),
                        owasp="A02: Cryptographic Failures",
                        cwe="CWE-327"
                    )
                )

                break

    return results