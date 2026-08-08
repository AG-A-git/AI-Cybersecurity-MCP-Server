import re


# Patterns for weak cryptographic algorithms
CRYPTO_PATTERNS = [
    (
        re.compile(r'\bhashlib\.md5\s*\(', re.IGNORECASE),
        "MD5",
        "High",
        95
    ),
    (
        re.compile(r'\bhashlib\.sha1\s*\(', re.IGNORECASE),
        "SHA-1",
        "High",
        95
    ),
    (
        re.compile(r'\bDES\s*\(', re.IGNORECASE),
        "DES",
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

    except FileNotFoundError:
        return results

    for line_number, line in enumerate(lines, start=1):

        for pattern, algorithm, severity, confidence in CRYPTO_PATTERNS:

            if pattern.search(line):

                results.append({
                    "file": file_path,
                    "line": line_number,
                    "vulnerability": "Weak Cryptography",
                    "severity": severity,
                    "confidence": confidence,
                    "code": line.strip(),
                    "algorithm": algorithm
                })

    return results
if __name__ == "__main__":
    results = scan_crypto(
        "scanner/test_files/crypto_test.py"
    )

    for result in results:
        print(result)