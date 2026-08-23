import re

from scanner.finding import create_finding


LDAP_PATTERNS = [
    (
        re.compile(
            r'["\']\s*\(\s*uid\s*=\s*["\']?\s*\+\s*[A-Za-z_][A-Za-z0-9_]*',
            re.IGNORECASE
        ),
        "High",
        90
    ),
    (
        re.compile(
            r'["\']\s*\(\s*(cn|dn|mail|ou)\s*=\s*["\']?\s*\+\s*[A-Za-z_][A-Za-z0-9_]*',
            re.IGNORECASE
        ),
        "High",
        90
    ),
]


def scan_ldap(file_path):
    """
    Detect potential LDAP injection caused by directly
    concatenating variable-controlled input into LDAP filters.
    """

    results = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

    except (FileNotFoundError, OSError):
        return results

    for line_number, line in enumerate(lines, start=1):

        for pattern, severity, confidence in LDAP_PATTERNS:

            if pattern.search(line):

                results.append(
                    create_finding(
                        file_name=file_path,
                        line_number=line_number,
                        vulnerability_type="LDAP Injection",
                        severity=severity,
                        confidence=confidence,
                        code=line.strip(),
                        owasp="A03: Injection",
                        cwe="CWE-90"
                    )
                )

                break

    return results