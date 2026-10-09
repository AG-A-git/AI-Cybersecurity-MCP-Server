
import re

from scanner.context import (
    build_rule_context,
    get_source_context,
    is_variable_derived_from,
)
from scanner.finding import create_finding


USER_INPUT_VARIABLE_NAMES = {
    "userInput",
    "user_input",
}

USER_INPUT_NAMES = re.compile(
    r"\b(userInput|user_input)\b",
    re.IGNORECASE,
)

REQUEST_INPUT_SOURCES = re.compile(
    r"\b(?:request\.(?:args|form|values|json|data|query_params)|"
    r"req\.(?:query|body|params)|"
    r"get_json\s*\(|"
    r"input\s*\()",
    re.IGNORECASE,
)

XSS_PATTERNS = [
    re.compile(
        r"\.innerHTML\s*=\s*([A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\.outerHTML\s*=\s*([A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE,
    ),
    re.compile(
        r"document\.write\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        re.IGNORECASE,
    ),
]


def _has_request_input_source(context, variable_name):
    """Check whether a variable's assignment history contains request input."""
    references = context.get("references", {})
    variables = {variable_name}
    pending = [variable_name]

    while pending:
        current = pending.pop()

        if REQUEST_INPUT_SOURCES.search(
            context.get("variables", {}).get(current, "")
        ):
            return True

        for referenced in references.get(current, []):
            if referenced not in variables:
                variables.add(referenced)
                pending.append(referenced)

    return False


def scan_xss(file_path):
    """Detect potential XSS involving user-controlled data."""
    results = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except (FileNotFoundError, OSError, UnicodeError):
        return results

    try:
        context = build_rule_context(file_path)
    except (SyntaxError, ValueError, OSError, UnicodeError):
        context = {"lines": [line.rstrip("\n") for line in lines]}

    for line_number, line in enumerate(lines, start=1):
        for pattern in XSS_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            assigned_variable = match.group(1)
            is_user_controlled = (
                bool(USER_INPUT_NAMES.search(assigned_variable))
                or is_variable_derived_from(
                    context,
                    assigned_variable,
                    USER_INPUT_VARIABLE_NAMES,
                )
                or _has_request_input_source(context, assigned_variable)
            )

            if is_user_controlled:
                finding = create_finding(
                    file_name=file_path,
                    line_number=line_number,
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    severity="High",
                    confidence=80,
                    code=line.strip(),
                    owasp="A03: Injection",
                    cwe="CWE-79",
                )

                finding["source_context"] = get_source_context(
                    context,
                    line_number,
                )
                results.append(finding)

            break

    return results