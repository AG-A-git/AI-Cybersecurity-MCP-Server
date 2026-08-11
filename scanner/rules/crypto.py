import re


CRYPTO_PATTERNS = [
    (
        re.compile(r'\bhashlib\.md5\s*\(', re.IGNORECASE),
        "High",
        95
    ),
    (
        re.compile(r'\bhashlib\.sha1\s*\(', re.IGNORECASE),
        "High",
        95
    ),
    (
        re.compile(r'\bDES\s*\(', re.IGNORECASE),
        "High",
        90
    ),
]


def scan_crypto(file_path):
    """
    Detect weak cryptographic algorithms
    in source code.
    """

    results = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

    except (FileNotFoundError, OSError):
        return results

    for line_number, line in enumerate(lines, start=1):

        for pattern, severity, confidence in CRYPTO_PATTERNS:

            if pattern.search(line):

                results.append({
                    "file": str(file_path),
                    "line": line_number,
                    "vulnerability": "Weak Cryptography",
                    "severity": severity,
                    "confidence": confidence,
                    "code": line.strip()
                })

                break

    return results