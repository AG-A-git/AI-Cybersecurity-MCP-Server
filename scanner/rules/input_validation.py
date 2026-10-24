
import ast
import re

from scanner.context import (
    build_rule_context,
    get_source_context,
    is_variable_derived_from,
)
from scanner.finding import create_finding


# ---------------------------------------------------------
# Untrusted/user-controlled input sources
# ---------------------------------------------------------

USER_INPUT_PATTERNS = [
    r"\binput\s*\(",
    r"\brequest\.args\b",
    r"\brequest\.form\b",
    r"\brequest\.json\b",
    r"\brequest\.values\b",
    r"\brequest\.get\s*\(",
    r"\blocation\.search\b",
    r"\blocation\.hash\b",
    r"\bdocument\.URL\b",
]


# ---------------------------------------------------------
# Obvious validation mechanisms
# ---------------------------------------------------------

VALIDATION_PATTERNS = [
    r"\.isdigit\s*\(",
    r"\bre\.match\s*\(",
    r"\bre\.fullmatch\s*\(",
    r"\bin\s+\[",
    r"\bin\s+\(",
]


# ---------------------------------------------------------
# Sensitive operations / sinks
# ---------------------------------------------------------

SQL_SINK_PATTERNS = [
    r"\.execute\s*\(",
    r"\.executemany\s*\(",
]

COMMAND_SINK_PATTERNS = [
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bsubprocess\.(run|call|Popen)\s*\(",
]

XSS_SINK_PATTERNS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"\bdocument\.write\s*\(",
]

# Common parameter markers used by database drivers.
SQL_PLACEHOLDER_PATTERN = re.compile(
    r"%s|\?|:\w+|\$\d+|%\(\w+\)s"
)


def _matches_any(patterns, text):
    """Return True when any supplied regex matches the text."""
    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


def _extract_assigned_variable(line):
    """Extract a simple assigned variable."""
    match = re.match(
        r"\s*(?:const|let|var)?\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=",
        line,
    )

    if match:
        return match.group(1)

    return None


def _contains_variable(variable, line):
    """Check whether a variable name appears in a line."""
    return re.search(
        rf"\b{re.escape(variable)}\b",
        line,
        re.IGNORECASE,
    ) is not None


def _parameterized_sql_execute_lines(lines):
    """
    Identify execute/executemany calls whose SQL is a literal containing
    a parameter placeholder and whose parameter values are separate args.

    AST line ranges handle multiline calls. Dynamic SQL expressions are
    not considered safe by this helper.
    """
    try:
        tree = ast.parse("".join(lines))
    except (SyntaxError, ValueError, TypeError):
        return set()

    parameterized_lines = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Attribute):
            continue

        if node.func.attr not in {"execute", "executemany"}:
            continue

        if len(node.args) < 2:
            continue

        query_node = node.args[0]

        # Accept only a literal SQL string, not dynamically built SQL.
        if not isinstance(query_node, ast.Constant):
            continue

        if not isinstance(query_node.value, str):
            continue

        if not SQL_PLACEHOLDER_PATTERN.search(query_node.value):
            continue

        # The SQL call is safe from this rule's taint-based SQL finding.
        # Include all lines of the call to support multiline formatting.
        start = node.lineno
        end = getattr(node, "end_lineno", node.lineno)
        parameterized_lines.update(range(start, end + 1))

    return parameterized_lines


def _add_finding(
    findings,
    file_path,
    line_number,
    vulnerability_type,
    confidence,
    code,
    cwe,
    context=None,
):
    """Create a standardized vulnerability finding."""
    finding = create_finding(
        file_name=file_path,
        line_number=line_number,
        vulnerability_type=vulnerability_type,
        severity="High",
        confidence=confidence,
        code=code,
        owasp="A03: Injection",
        cwe=cwe,
    )

    if context is not None:
        finding["source_context"] = get_source_context(
            context,
            line_number,
        )

    findings.append(finding)


def scan_input_validation(file_path):
    """
    Track simple user-controlled input flows to sensitive sinks.

    Parameterized SQL calls with a literal query and separate parameter
    arguments are excluded from SQL injection findings. This does not
    treat dynamically constructed SQL as safe.
    """
    findings = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()
    except (FileNotFoundError, OSError):
        return findings

    try:
        context = build_rule_context(file_path)
    except (
        SyntaxError,
        ValueError,
        OSError,
        UnicodeError,
    ):
        context = {
            "lines": [
                line.rstrip("\n")
                for line in lines
            ]
        }

    parameterized_sql_lines = _parameterized_sql_execute_lines(lines)

    user_input_variables = set()
    tainted_variables = set()
    validated_variables = set()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped:
            continue

        assigned_variable = _extract_assigned_variable(stripped)

        # 1. Detect variables assigned directly from user input.
        if _matches_any(USER_INPUT_PATTERNS, stripped):
            if assigned_variable:
                user_input_variables.add(assigned_variable)
                tainted_variables.add(assigned_variable)

        # 2. Track variable propagation.
        if assigned_variable:
            if is_variable_derived_from(
                context,
                assigned_variable,
                user_input_variables,
            ):
                tainted_variables.add(assigned_variable)

            if is_variable_derived_from(
                context,
                assigned_variable,
                validated_variables,
            ):
                validated_variables.add(assigned_variable)

        # 3. Detect obvious validation evidence.
        if _matches_any(VALIDATION_PATTERNS, stripped):
            for variable in list(tainted_variables):
                if _contains_variable(variable, stripped):
                    validated_variables.add(variable)

        # 4. Detect direct source-to-sink flows.
        is_parameterized_sql_line = (
            line_number in parameterized_sql_lines
        )

        if (
            _matches_any(SQL_SINK_PATTERNS, stripped)
            and not is_parameterized_sql_line
            and _matches_any(USER_INPUT_PATTERNS, stripped)
        ):
            _add_finding(
                findings=findings,
                file_path=file_path,
                line_number=line_number,
                vulnerability_type="SQL Injection",
                confidence=90,
                code=stripped,
                cwe="CWE-89",
                context=context,
            )

        if (
            _matches_any(COMMAND_SINK_PATTERNS, stripped)
            and _matches_any(USER_INPUT_PATTERNS, stripped)
        ):
            _add_finding(
                findings=findings,
                file_path=file_path,
                line_number=line_number,
                vulnerability_type="Command Injection",
                confidence=90,
                code=stripped,
                cwe="CWE-78",
                context=context,
            )

        if (
            _matches_any(XSS_SINK_PATTERNS, stripped)
            and _matches_any(USER_INPUT_PATTERNS, stripped)
        ):
            _add_finding(
                findings=findings,
                file_path=file_path,
                line_number=line_number,
                vulnerability_type="Cross-Site Scripting (XSS)",
                confidence=85,
                code=stripped,
                cwe="CWE-79",
                context=context,
            )

        # 5. Detect tainted variables reaching sinks.
        for variable in list(tainted_variables):
            if not _contains_variable(variable, stripped):
                continue

            is_validated = variable in validated_variables

            if (
                _matches_any(SQL_SINK_PATTERNS, stripped)
                and not is_parameterized_sql_line
            ):
                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="SQL Injection",
                    confidence=65 if is_validated else 90,
                    code=stripped,
                    cwe="CWE-89",
                    context=context,
                )

            if _matches_any(COMMAND_SINK_PATTERNS, stripped):
                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="Command Injection",
                    confidence=65 if is_validated else 90,
                    code=stripped,
                    cwe="CWE-78",
                    context=context,
                )

            if _matches_any(XSS_SINK_PATTERNS, stripped):
                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    confidence=60 if is_validated else 85,
                    code=stripped,
                    cwe="CWE-79",
                    context=context,
                )

    return findings
