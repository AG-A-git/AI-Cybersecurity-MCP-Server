import re

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


def _matches_any(patterns, text):
    """Return True when any supplied regex matches the text."""
    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


def _extract_assigned_variable(line):
    """
    Extract a simple assigned variable.

    Examples:
        user_id = request.args.get("id")
        query = "SELECT ..." + user_id
        const name = location.search
    """

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


def _add_finding(
    findings,
    file_path,
    line_number,
    vulnerability_type,
    confidence,
    code,
    cwe,
):
    """Create a standardized vulnerability finding."""

    findings.append(
        create_finding(
            file_name=file_path,
            line_number=line_number,
            vulnerability_type=vulnerability_type,
            severity="High",
            confidence=confidence,
            code=code,
            owasp="A03: Injection",
            cwe=cwe,
        )
    )


def scan_input_validation(file_path):
    """
    Supporting input-flow analysis.

    Tracks obvious user-controlled input and follows simple
    source -> variable -> variable -> sink relationships.

    This is intentionally lightweight rule-based analysis.
    It does not attempt full taint analysis.

    Validation evidence lowers confidence but does not claim
    that the code is completely safe.

    This rule does NOT create a new vulnerability category.
    Findings remain existing categories such as:

        - SQL Injection
        - Command Injection
        - Cross-Site Scripting (XSS)
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

    # Variables directly assigned from user input.
    user_input_variables = set()

    # Variables derived from already-tainted variables.
    tainted_variables = set()

    # Variables for which an obvious validation step was seen.
    validated_variables = set()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        if not stripped:
            continue

        # ---------------------------------------------------------
        # 1. Detect variables assigned directly from user input.
        # ---------------------------------------------------------

        assigned_variable = _extract_assigned_variable(stripped)

        if _matches_any(USER_INPUT_PATTERNS, stripped):

            if assigned_variable:
                user_input_variables.add(assigned_variable)
                tainted_variables.add(assigned_variable)

        # ---------------------------------------------------------
        # 2. Track simple variable-to-variable propagation.
        #
        # Example:
        #
        # user_id = request.args.get("id")
        # query = "SELECT ..." + user_id
        #
        # This records:
        #
        # user_id -> query
        # ---------------------------------------------------------

        if assigned_variable:

            for variable in list(tainted_variables):

                if assigned_variable == variable:
                    continue

                if _contains_variable(variable, stripped):

                    tainted_variables.add(assigned_variable)

                    # If the source variable was validated,
                    # preserve that evidence for the derived
                    # variable as well.
                    if variable in validated_variables:
                        validated_variables.add(
                            assigned_variable
                        )

        # ---------------------------------------------------------
        # 3. Detect obvious validation.
        #
        # Examples:
        #
        # user_id.isdigit()
        # re.match(...)
        # command in ["date", "uptime"]
        #
        # This is evidence of validation/constraint only.
        # ---------------------------------------------------------

        if _matches_any(VALIDATION_PATTERNS, stripped):

            for variable in list(tainted_variables):

                if _contains_variable(variable, stripped):
                    validated_variables.add(variable)

        # ---------------------------------------------------------
        # 4. Detect direct source -> sink flows.
        #
        # Example:
        #
        # cursor.execute(request.args.get("id"))
        # os.system(request.args.get("cmd"))
        # element.innerHTML = location.search
        # ---------------------------------------------------------

        if _matches_any(SQL_SINK_PATTERNS, stripped):

            if _matches_any(USER_INPUT_PATTERNS, stripped):

                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="SQL Injection",
                    confidence=90,
                    code=stripped,
                    cwe="CWE-89",
                )

        if _matches_any(COMMAND_SINK_PATTERNS, stripped):

            if _matches_any(USER_INPUT_PATTERNS, stripped):

                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="Command Injection",
                    confidence=90,
                    code=stripped,
                    cwe="CWE-78",
                )

        if _matches_any(XSS_SINK_PATTERNS, stripped):

            if _matches_any(USER_INPUT_PATTERNS, stripped):

                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    confidence=85,
                    code=stripped,
                    cwe="CWE-79",
                )

        # ---------------------------------------------------------
        # 5. Detect tainted variables reaching sinks.
        #
        # Example:
        #
        # user_id = request.args.get("id")
        # query = "SELECT ..." + user_id
        # cursor.execute(query)
        #
        # The scanner follows:
        #
        # user_id -> query -> execute()
        # ---------------------------------------------------------

        for variable in list(tainted_variables):

            if not _contains_variable(variable, stripped):
                continue

            is_validated = variable in validated_variables

            # -----------------------------------------------------
            # SQL Injection
            # -----------------------------------------------------

            if _matches_any(SQL_SINK_PATTERNS, stripped):

                confidence = 65 if is_validated else 90

                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="SQL Injection",
                    confidence=confidence,
                    code=stripped,
                    cwe="CWE-89",
                )

            # -----------------------------------------------------
            # Command Injection
            # -----------------------------------------------------

            if _matches_any(COMMAND_SINK_PATTERNS, stripped):

                confidence = 65 if is_validated else 90

                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="Command Injection",
                    confidence=confidence,
                    code=stripped,
                    cwe="CWE-78",
                )

            # -----------------------------------------------------
            # Cross-Site Scripting
            # -----------------------------------------------------

            if _matches_any(XSS_SINK_PATTERNS, stripped):

                confidence = 60 if is_validated else 85

                _add_finding(
                    findings=findings,
                    file_path=file_path,
                    line_number=line_number,
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    confidence=confidence,
                    code=stripped,
                    cwe="CWE-79",
                )

    return findings