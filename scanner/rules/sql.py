import re


SQL_PATTERNS = [
    re.compile(
        r'(SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+',
        re.IGNORECASE
    ),
    re.compile(
        r'\b(query|sql)\s*=\s*["\'].*["\']\s*\+',
        re.IGNORECASE
    ),
    re.compile(
        r'\b(execute|cursor\.execute)\s*\([^)]*\+[^)]*\)',
        re.IGNORECASE
    ),
]


def scan_sql(file_path):
    results = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except FileNotFoundError:
        return results

    for line_number, line in enumerate(lines, start=1):
        for pattern in SQL_PATTERNS:
            if pattern.search(line):
                results.append({
                    "file": file_path,
                    "line": line_number,
                    "vulnerability": "SQL Injection",
                    "severity": "Critical",
                    "confidence": 96,
                    "code": line.strip()
                })
                break

    return results