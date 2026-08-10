import re


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

    for line_number, line in enumerate(lines, start=1):

        for pattern in XSS_PATTERNS:

            match = pattern.search(line)

            if match:
                assigned_variable = match.group(1)

                if USER_INPUT_NAMES.search(assigned_variable):

                    results.append({
                        "file": str(file_path),
                        "line": line_number,
                        "vulnerability": "Cross Site Scripting",
                        "severity": "High",
                        "confidence": 80,
                        "code": line.strip()
                    })

                break

    return results