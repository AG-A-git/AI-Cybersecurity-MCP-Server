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