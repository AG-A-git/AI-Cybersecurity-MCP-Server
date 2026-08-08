import re


SQL_PATTERNS = [
    r"cursor\.execute\s*\(",
    r"execute\s*\(",
    r"SELECT.*\+",
    r"INSERT.*\+",
    r"UPDATE.*\+",
    r"DELETE.*\+",
]


def detect_sql_injection(file_path, code):
    """
    Detect simple SQL Injection patterns.
    """

    findings = []

    lines = code.splitlines()

    for line_number, line in enumerate(lines, start=1):

        for pattern in SQL_PATTERNS:

            if re.search(pattern, line, re.IGNORECASE):

                findings.append({
                    "file": file_path,
                    "line": line_number,
                    "vulnerability": "SQL Injection",
                    "severity": "Critical",
                    "confidence": 95,
                    "code": line.strip()
                })

                break

    return findings