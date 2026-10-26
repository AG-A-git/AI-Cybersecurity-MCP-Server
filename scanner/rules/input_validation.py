
import ast
import re

from scanner.context import (
    build_rule_context,
    get_source_context,
    is_variable_derived_from,
)
from scanner.finding import create_finding


# ---------------------------------------------------------
# User-controlled input sources
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
    r"\bwindow\.location\b",
    r"\bURLSearchParams\s*\(",
]

# ---------------------------------------------------------
# Validation indicators
# ---------------------------------------------------------

VALIDATION_PATTERNS = [
    r"\.isdigit\s*\(",
    r"\bre\.match\s*\(",
    r"\bre\.fullmatch\s*\(",
    r"\bin\s+\[",
    r"\bin\s+\(",
]

# ---------------------------------------------------------
# Sensitive sinks
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

SQL_PLACEHOLDER_PATTERN = re.compile(
    r"%s|\?|:\w+|\$\d+|%\(\w+\)s"
)


def _matches_any(patterns, text):
    """Return True if any regex matches the text."""
    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


def _extract_assigned_variable(line):
    """Extract a simple Python or JavaScript assignment target."""
    match = re.match(
        r"\s*(?:(?:const|let|var)\s+)?"
        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*="
        r"(?!=|>)",
        line,
    )
    return match.group(1) if match else None


def _contains_variable(variable, line):
    """Check for a complete variable identifier."""
    return re.search(
        rf"(?<![A-Za-z0-9_$]){re.escape(variable)}"
        rf"(?![A-Za-z0-9_$])",
        line,
    ) is not None


def _parameterized_sql_execute_lines(lines):
    """
    Identify Python execute/executemany calls with literal SQL,
    a recognized placeholder, and a separate parameter argument.

    This is a heuristic, not a complete database-driver analysis.
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

        if not isinstance(query_node, ast.Constant):
            continue

        if not isinstance(query_node.value, str):
            continue

        if not SQL_PLACEHOLDER_PATTERN.search(query_node.value):
            continue

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
    evidence=None,
):
    """Create a standardized finding without duplicate entries."""
    severity_by_type = {
        "SQL Injection": "Critical",
        "Command Injection": "Critical",
        "Cross-Site Scripting (XSS)": "High",
    }

    finding = create_finding(
        file_name=str(file_path),
        line_number=line_number,
        vulnerability_type=vulnerability_type,
        severity=severity_by_type[vulnerability_type],
        confidence=confidence,
        code=code,
        owasp="A03: Injection",
        cwe=cwe,
        evidence=evidence,
    )

    if context is not None:
        finding["source_context"] = get_source_context(
            context,
            line_number,
        )

    # Avoid duplicates produced by direct-source and taint checks.
    fingerprint = finding["fingerprint"]

    if not any(
        existing.get("fingerprint") == fingerprint
        for existing in findings
    ):
        findings.append(finding)


def _scan_javascript_xss(lines, file_path):
    """
    Detect simple JavaScript source-to-sink flows.

    Example:
        const name = location.search;
        element.innerHTML = name;

    This lightweight scanner does not replace a JavaScript AST
    or full interprocedural taint analysis.
    """
    findings = []
    tainted_variables = set()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("//"):
            continue

        assigned_variable = _extract_assigned_variable(stripped)

        # Record assignments that directly use browser-controlled input.
        if assigned_variable and _matches_any(
            USER_INPUT_PATTERNS, stripped
        ):
            tainted_variables.add(assigned_variable)

        # Track simple propagation, such as:
        # const copiedName = name;
        elif assigned_variable and any(
            _contains_variable(variable, stripped)
            for variable in tainted_variables
        ):
            tainted_variables.add(assigned_variable)

        if not _matches_any(XSS_SINK_PATTERNS, stripped):
            continue

        direct_source = _matches_any(
            USER_INPUT_PATTERNS, stripped
        )

        tainted_sink = any(
            _contains_variable(variable, stripped)
            for variable in tainted_variables
        )

        if not direct_source and not tainted_sink:
            continue

        _add_finding(
            findings=findings,
            file_path=file_path,
            line_number=line_number,
            vulnerability_type="Cross-Site Scripting (XSS)",
            confidence=85 if direct_source else 80,
            code=stripped,
            cwe="CWE-79",
            evidence={
                "source": "browser-controlled input",
                "sink": "HTML injection sink",
                "sink_line": line_number,
                "tainted_variables": sorted(tainted_variables),
                "reason": (
                    "A potentially user-controlled value reaches "
                    "an HTML injection sink. Review sanitization "
                    "and application context."
                ),
            },
        )

    return findings


def scan_input_validation(file_path):
    """
    Detect simple user-input flows to SQL, command, and XSS sinks.

    Supports Python source files and lightweight JavaScript XSS
    detection. Parameterized Python SQL calls with a literal query
    and separate parameter argument are excluded from SQL findings.
    """
    findings = []

    # pathlib.Path objects do not have .lower() or .endswith().
    path_string = str(file_path)
    extension = path_string.lower()

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()
    except (FileNotFoundError, OSError, ValueError):
        return findings

    # Empty and null-byte-containing Python files should not crash.
    if not lines or not any(line.strip() for line in lines):
        return findings

    # Handle JavaScript separately because Python AST parsing cannot
    # parse JavaScript source code.
    if extension.endswith((".js", ".jsx", ".mjs")):
        return _scan_javascript_xss(lines, path_string)

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
                line.rstrip("\r\n")
                for line in lines
            ]
        }

    parameterized_sql_lines = _parameterized_sql_execute_lines(
        lines
    )

    user_input_variables = set()
    tainted_variables = set()
    validated_variables = set()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        assigned_variable = _extract_assigned_variable(stripped)

        # 1. Identify direct assignments from untrusted sources.
        if _matches_any(USER_INPUT_PATTERNS, stripped):
            if assigned_variable:
                user_input_variables.add(assigned_variable)
                tainted_variables.add(assigned_variable)

        # 2. Track variable propagation through the scanner context.
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

        # 3. Record basic validation indicators.
        if _matches_any(VALIDATION_PATTERNS, stripped):
            for variable in list(tainted_variables):
                if _contains_variable(variable, stripped):
                    validated_variables.add(variable)

        is_parameterized_sql_line = (
            line_number in parameterized_sql_lines
        )

        # 4. Check direct source-to-sink patterns.
        if (
            _matches_any(SQL_SINK_PATTERNS, stripped)
            and not is_parameterized_sql_line
            and _matches_any(USER_INPUT_PATTERNS, stripped)
        ):
            _add_finding(
                findings,
                file_path,
                line_number,
                "SQL Injection",
                90,
                stripped,
                "CWE-89",
                context,
            )

        if (
            _matches_any(COMMAND_SINK_PATTERNS, stripped)
            and _matches_any(USER_INPUT_PATTERNS, stripped)
        ):
            _add_finding(
                findings,
                file_path,
                line_number,
                "Command Injection",
                90,
                stripped,
                "CWE-78",
                context,
            )

        if (
            _matches_any(XSS_SINK_PATTERNS, stripped)
            and _matches_any(USER_INPUT_PATTERNS, stripped)
        ):
            _add_finding(
                findings,
                file_path,
                line_number,
                "Cross-Site Scripting (XSS)",
                85,
                stripped,
                "CWE-79",
                context,
            )

        # 5. Check tracked tainted variables at sensitive sinks.
        for variable in list(tainted_variables):
            if not _contains_variable(variable, stripped):
                continue

            is_validated = variable in validated_variables

            if (
                _matches_any(SQL_SINK_PATTERNS, stripped)
                and not is_parameterized_sql_line
            ):
                _add_finding(
                    findings,
                    file_path,
                    line_number,
                    "SQL Injection",
                    65 if is_validated else 90,
                    stripped,
                    "CWE-89",
                    context,
                )

            if _matches_any(COMMAND_SINK_PATTERNS, stripped):
                _add_finding(
                    findings,
                    file_path,
                    line_number,
                    "Command Injection",
                    65 if is_validated else 90,
                    stripped,
                    "CWE-78",
                    context,
                )

            if _matches_any(XSS_SINK_PATTERNS, stripped):
                _add_finding(
                    findings,
                    file_path,
                    line_number,
                    "Cross-Site Scripting (XSS)",
                    60 if is_validated else 85,
                    stripped,
                    "CWE-79",
                    context,
                )

    return findings
