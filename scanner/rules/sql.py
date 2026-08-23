import re

from scanner.finding import create_finding


SQL_PATTERNS = [
    # SQL keyword followed by string concatenation.
    re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE)\b'
        r'.*(["\']).*\+\s*[A-Za-z_][A-Za-z0-9_\.]*',
        re.IGNORECASE
    ),

    # Explicit SQL variable containing an actual SQL statement.
    # This prevents LDAP queries such as "(uid=" + username
    # from being classified as SQL injection.
    re.compile(
        r'\b(query|sql)\s*=\s*'
        r'(["\']).*?\b(SELECT|INSERT|UPDATE|DELETE)\b.*'
        r'\+\s*[A-Za-z_][A-Za-z0-9_\.]*',
        re.IGNORECASE
    ),

    # execute()/cursor.execute() with concatenated values.
    re.compile(
        r'\b(?:cursor\.)?execute\s*\('
        r'[^)]*\+\s*[A-Za-z_][A-Za-z0-9_\.]*[^)]*\)',
        re.IGNORECASE
    ),
]


def scan_sql(file_path):
    """
    Detect potential SQL injection caused by
    concatenating values into SQL statements.
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

        for pattern in SQL_PATTERNS:

            if pattern.search(line):

                results.append(
                    create_finding(
                        file_name=file_path,
                        line_number=line_number,
                        vulnerability_type="SQL Injection",
                        severity="Critical",
                        confidence=95,
                        code=line.strip(),
                        owasp="A03: Injection",
                        cwe="CWE-89"
                    )
                )

                break

    return results