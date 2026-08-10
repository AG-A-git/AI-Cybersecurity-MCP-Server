import re


def scan_input_validation(file_path):
    findings = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped:
            continue

        # Look for user-controlled input
        input_source = re.search(
            r'(request\.args\.get|request\.form\.get|request\.json\.get|input\s*\()',
            stripped
        )

        if not input_source:
            continue

        # Look for sensitive operations on the same line
        sensitive_operation = re.search(
            r'(execute\s*\(|os\.system\s*\(|subprocess|eval\s*\(|exec\s*\(|open\s*\()',
            stripped
        )

        if sensitive_operation:
            findings.append({
                "file": str(file_path),
                "line": line_number,
                "vulnerability": "Improper Input Validation",
                "severity": "Medium",
                "confidence": 75,
                "code": stripped
            })

    return findings