import re

from scanner.context import build_rule_context, get_source_context
from scanner.evidence import build_evidence
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


def _extract_concatenated_variable(line):
    """
    Extract the variable/expression appearing after '+'.

    Example:

        query = "SELECT * FROM users WHERE name='" + username

    Returns:

        username
    """

    match = re.search(
        r'\+\s*([A-Za-z_][A-Za-z0-9_\.]*)',
        line
    )

    if match:
        return match.group(1)

    return None


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

    try:
        context = build_rule_context(file_path)

    except (
        SyntaxError,
        ValueError,
        OSError,
        UnicodeError
    ):
        context = {
            "lines": [
                line.rstrip("\n")
                for line in lines
            ]
        }

    for line_number, line in enumerate(lines, start=1):

        for pattern in SQL_PATTERNS:

            if pattern.search(line):

                tainted_variable = _extract_concatenated_variable(
                    line
                )

                evidence = build_evidence(
                    source=tainted_variable,
                    source_line=line_number,
                    tainted_variable=tainted_variable,
                    sink="SQL statement construction",
                    sink_line=line_number,
                    reason=(
                        "SQL statement contains string concatenation "
                        "with a variable or expression."
                    ),
                )

                finding = create_finding(
                    file_name=file_path,
                    line_number=line_number,
                    vulnerability_type="SQL Injection",
                    severity="Critical",
                    confidence=95,
                    code=line.strip(),
                    owasp="A03: Injection",
                    cwe="CWE-89",
                    evidence=evidence
                )

                finding["source_context"] = get_source_context(
                    context,
                    line_number
                )

                results.append(finding)

                break

    return results