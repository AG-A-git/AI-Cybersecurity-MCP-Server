import re

from scanner.context import build_rule_context, get_source_context
from scanner.finding import create_finding


USER_INPUT_NAMES = re.compile(
    r'\b(userInput|user_input|input|request|req|data|query|param|parameter|search|message)\b',
    re.IGNORECASE
)


XSS_PATTERNS = [
    re.compile(
        r'\.innerHTML\s*=\s*([A-Za-z_][A-Za-z0-9_]*)',
        re.IGNORECASE
    ),
    re.compile(
        r'document\.write\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)',
        re.IGNORECASE
    ),
    re.compile(
        r'\.outerHTML\s*=\s*([A-Za-z_][A-Za-z0-9_]*)',
        re.IGNORECASE
    ),
]


def scan_xss(file_path):
    """
    Detect potential Cross-Site Scripting patterns
    involving potentially user-controlled data.
    """

    results = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
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

        for pattern in XSS_PATTERNS:

            match = pattern.search(line)

            if match:
                assigned_variable = match.group(1)

                if USER_INPUT_NAMES.search(assigned_variable):

                    finding = create_finding(
                        file_name=file_path,
                        line_number=line_number,
                        vulnerability_type="Cross-Site Scripting (XSS)",
                        severity="High",
                        confidence=80,
                        code=line.strip(),
                        owasp="A03: Injection",
                        cwe="CWE-79"
                    )

                    finding["source_context"] = get_source_context(
                        context,
                        line_number
                    )

                    results.append(finding)

                break

    return results
