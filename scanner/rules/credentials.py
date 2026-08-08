import re

# Regex patterns for hardcoded credentials
CREDENTIAL_PATTERNS = [
    r'password\s*=\s*["\'].+["\']',
    r'passwd\s*=\s*["\'].+["\']',
    r'pwd\s*=\s*["\'].+["\']',
    r'api_key\s*=\s*["\'].+["\']',
    r'apikey\s*=\s*["\'].+["\']',
    r'access_token\s*=\s*["\'].+["\']',
    r'token\s*=\s*["\'].+["\']',
    r'secret\s*=\s*["\'].+["\']',
    r'client_secret\s*=\s*["\'].+["\']',
]


def detect_hardcoded_credentials(code):
    """
    Detect hardcoded credentials in source code.
    """

    findings = []

    lines = code.splitlines()

    for line_number, line in enumerate(lines, start=1):

        for pattern in CREDENTIAL_PATTERNS:

            if re.search(pattern, line, re.IGNORECASE):

                findings.append({
                    "type": "Hardcoded Credential",
                    "line": line_number,
                    "severity": "High",
                    "confidence": "High",
                    "message": "Possible hardcoded credential found."
                })

                break

    return findings

import re


def scan_credentials(file_path):
    """
    Detect hardcoded credentials and secrets.
    """

    results = []

    patterns = [
        re.compile(
            r'\bpassword\s*=\s*["\'][^"\']+["\']',
            re.IGNORECASE
        ),
        re.compile(
            r'\bapi_key\s*=\s*["\'][^"\']+["\']',
            re.IGNORECASE
        ),
        re.compile(
            r'\bsecret_key\s*=\s*["\'][^"\']+["\']',
            re.IGNORECASE
        ),
        re.compile(
            r'\btoken\s*=\s*["\'][^"\']+["\']',
            re.IGNORECASE
        ),
    ]

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

    except FileNotFoundError:
        return results

    for line_number, line in enumerate(lines, start=1):

        for pattern in patterns:

            if pattern.search(line):

                results.append({
                    "file": file_path,
                    "line": line_number,
                    "vulnerability": "Hardcoded Credential",
                    "severity": "High",
                    "confidence": 95,
                    "code": line.strip()
                })

                break

    return results
if __name__ == "__main__":
    results = scan_credentials(
        "scanner/test_files/credentials_test.py"
    )

    for result in results:
        print(result)