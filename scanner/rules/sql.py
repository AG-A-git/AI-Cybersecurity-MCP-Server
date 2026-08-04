import re

# Patterns that may indicate SQL Injection
SQL_PATTERNS = [
    r'cursor\.execute\s*\(',
    r'execute\s*\(',
    r'SELECT.*\+',
    r'INSERT.*\+',
    r'UPDATE.*\+',
    r'DELETE.*\+',
]


def detect_sql_injection(code):
    """
    Detect possible SQL Injection vulnerabilities.
    Returns a list of findings.
    """

    findings = []

    lines = code.splitlines()

    for line_number, line in enumerate(lines, start=1):

        # Check SQL patterns
        for pattern in SQL_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):

                findings.append({
                    "type": "SQL Injection",
                    "line": line_number,
                    "severity": "High",
                    "confidence": "Medium",
                    "message": "Possible SQL Injection detected."
                })

                break

        # Detect SQL string concatenation
        if (
            ("SELECT" in line.upper() or
             "INSERT" in line.upper() or
             "UPDATE" in line.upper() or
             "DELETE" in line.upper())
            and "+" in line
        ):

            findings.append({
                "type": "SQL Injection",
                "line": line_number,
                "severity": "High",
                "confidence": "High",
                "message": "SQL query built using string concatenation."
            })

    return findings