from scanner.severity import get_severity

SQL_PATTERNS = [
    "cursor.execute(",
    "SELECT" + " ",
    ".format(",
    'f"',
    "f'",
    "%s",
]


# Patterns that may indicate SQL Injection
SQL_PATTERNS = [
    r'cursor\.execute\s*\(',
    r'execute\s*\(',
    r'SELECT.*\+',
    r'INSERT.*\+',
    r'UPDATE.*\+',
    r'DELETE.*\+',
]

def detect_sql_injection(file_path, code):
    """
    Detect simple SQL Injection patterns.
    """

    findings = []

    lines = code.splitlines()

    for line_number, line in enumerate(lines, start=1):

        for pattern in SQL_PATTERNS:

            if pattern in line:

                findings.append({
                    "file": file_path,
                    "line": line_number,
                    "vulnerability": "SQL Injection",
                    "severity": get_severity("SQL Injection"),
                    "confidence": 95,
                    "code": line.strip()
                })

                break

    return findings