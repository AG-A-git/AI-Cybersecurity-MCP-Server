import re


CREDENTIAL_PATTERNS = [
    re.compile(
        r'\bpassword\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\bpasswd\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\bpwd\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\bapi[_-]?key\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\bapikey\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\baccess[_-]?token\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\btoken\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\bsecret[_-]?key\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\bsecret\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
    re.compile(
        r'\bclient[_-]?secret\s*=\s*["\'][^"\']+["\']',
        re.IGNORECASE
    ),
]


def scan_credentials(file_path):
    """
    Detect potential hardcoded credentials and secrets.
    """

    results = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

    except (FileNotFoundError, OSError):
        return results

    for line_number, line in enumerate(lines, start=1):

        for pattern in CREDENTIAL_PATTERNS:

            if pattern.search(line):

                results.append({
                    "file": str(file_path),
                    "line": line_number,
                    "vulnerability": "Hardcoded Credentials",
                    "severity": "High",
                    "confidence": 90,
                    "code": line.strip()
                })

                break

    return results