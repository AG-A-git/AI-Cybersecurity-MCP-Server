
import re

from scanner.context import (
    build_rule_context,
    get_source_context,
    is_variable_derived_from,
)
from scanner.evidence import build_evidence
from scanner.finding import create_finding


USER_INPUT_NAMES = {
    "user_input",
    "input",
    "username",
    "user_id",
    "user_command",
    "id",
}


SQL_KEYWORDS = r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b"

# Detect SQL statements built through unsafe string concatenation,
# f-strings, and .format().
SQL_PATTERNS = [
    # SQL statement concatenation.
    re.compile(
        SQL_KEYWORDS
        + r".*(?:[\"']).*\+\s*[A-Za-z_][A-Za-z0-9_\.]*",
        re.IGNORECASE,
    ),

    # SQL variable assigned a concatenated SQL statement.
    re.compile(
        r"\b(?:query|sql)\s*=\s*"
        r"(?:[\"']).*?"
        + SQL_KEYWORDS
        + r".*\+\s*[A-Za-z_][A-Za-z0-9_\.]*",
        re.IGNORECASE,
    ),

    # SQL f-string assigned to a query variable.
    re.compile(
        r"\b(?:query|sql)\s*=\s*f[\"']"
        r"(?=.*?"
        + SQL_KEYWORDS
        + r").*?\{[^{}]+\}",
        re.IGNORECASE,
    ),

    # SQL query assigned using .format().
    re.compile(
        r"\b(?:query|sql)\s*=\s*[\"']"
        r"(?=.*?"
        + SQL_KEYWORDS
        + r").*?[\"']\s*\.format\s*\(",
        re.IGNORECASE,
    ),

    # execute() called with a concatenated SQL statement.
    re.compile(
        r"\b(?:cursor\.)?execute\s*\("
        r"[^)]*\+\s*[A-Za-z_][A-Za-z0-9_\.]*[^)]*\)",
        re.IGNORECASE,
    ),
]


def _extract_concatenated_variable(line):
    """Extract a variable from concatenation, f-strings, or .format()."""

    # String concatenation: "..." + username
    match = re.search(
        r"\+\s*([A-Za-z_][A-Za-z0-9_\.]*)",
        line,
    )
    if match:
        return match.group(1)

    # F-string interpolation: f"...{username}..."
    match = re.search(
        r"\{([A-Za-z_][A-Za-z0-9_\.]*)\}",
        line,
    )
    if match:
        return match.group(1)

    # String formatting: "...{}".format(username)
    match = re.search(
        r"\.format\s*\(\s*([A-Za-z_][A-Za-z0-9_\.]*)",
        line,
    )
    if match:
        return match.group(1)

    return None


def _is_parameterized_query(line):
    """
    Avoid flagging common parameterized execute() calls.

    Examples:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    """
    return bool(
        re.search(
            r"\b(?:cursor\.)?execute\s*\(\s*"
            r"[\"'].*?"
            r"(?:%s|\?|:\w+|\$\d+)"
            r".*?[\"']\s*,",
            line,
            re.IGNORECASE,
        )
    )


def scan_sql(file_path):
    """
    Detect potential SQL injection in dynamically constructed SQL queries.

    This is a lightweight static-analysis rule. Findings should be reviewed
    in context, particularly when a query uses a custom database wrapper.
    """
    results = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore",
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
        UnicodeError,
    ):
        context = {
            "lines": [line.rstrip("\n") for line in lines]
        }

    for line_number, line in enumerate(lines, start=1):
        # Parameterized queries are not flagged by this rule.
        if _is_parameterized_query(line):
            continue

        matched = any(
            pattern.search(line)
            for pattern in SQL_PATTERNS
        )
        if not matched:
            continue

        tainted_variable = _extract_concatenated_variable(line)

        is_tainted = (
            tainted_variable is not None
            and is_variable_derived_from(
                context,
                tainted_variable,
                USER_INPUT_NAMES,
            )
        )

        evidence = build_evidence(
            source=tainted_variable,
            source_line=line_number,
            tainted_variable=tainted_variable,
            sink="SQL statement construction",
            sink_line=line_number,
            reason=(
                "SQL statement construction includes a variable "
                "through concatenation, f-string interpolation, "
                "or .format(). Verify whether the value is "
                "parameterized or safely validated."
            ),
        )

        finding = create_finding(
            file_name=file_path,
            line_number=line_number,
            vulnerability_type="SQL Injection",
            severity="Critical",
            confidence=90 if is_tainted else 85,
            code=line.strip(),
            owasp="A03: Injection",
            cwe="CWE-89",
            evidence=evidence,
        )

        finding["source_context"] = get_source_context(
            context,
            line_number,
        )

        results.append(finding)

    return results
