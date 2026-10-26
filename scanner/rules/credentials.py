
import re

from scanner.context import build_rule_context, get_source_context
from scanner.finding import create_finding


# Credential-like variable and dictionary key names.
SECRET_NAMES = (
    r"password|passwd|pwd|secret|secret_key|api_key|apikey|"
    r"token|access_token|private_key|client_secret|"
    r"aws_secret_access_key"
)

# Match assignments: api_key = "..." or password = '...'.
HARDCODED_SECRET_PATTERN = re.compile(
    rf"\b({SECRET_NAMES})\b\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# Match dictionary entries: "api_key": "..." or 'token': '...'.
DICTIONARY_SECRET_PATTERN = re.compile(
    rf"[\"']({SECRET_NAMES})[\"']\s*:\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# Common placeholder values that should not normally be reported.
SAFE_VALUES = {
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "value",
    "example",
    "test",
    "testing",
    "changeme",
    "your_password",
    "your_secret",
    "your_api_key",
}


def scan_credentials(file_path):
    """Detect potential hardcoded credentials and secrets."""
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
        matches = []

        assignment_match = HARDCODED_SECRET_PATTERN.search(line)
        dictionary_match = DICTIONARY_SECRET_PATTERN.search(line)

        if assignment_match:
            matches.append(assignment_match)

        if dictionary_match:
            matches.append(dictionary_match)

        seen_values = set()

        for match in matches:
            secret_name = match.group(1).lower()
            secret_value = match.group(2).strip()

            if not secret_value:
                continue

            # Ignore obvious placeholder values.
            if secret_value.lower() in SAFE_VALUES:
                continue

            # Avoid duplicate findings for the same key/value on a line.
            value_key = (secret_name, secret_value)
            if value_key in seen_values:
                continue
            seen_values.add(value_key)

            finding = create_finding(
                file_name=file_path,
                line_number=line_number,
                vulnerability_type="Hardcoded Credentials / Secrets",
                severity="High",
                confidence=90,
                code=line.strip(),
                owasp="A07: Identification and Authentication Failures",
                cwe="CWE-798",
            )

            finding["source_context"] = get_source_context(
                context,
                line_number,
            )

            results.append(finding)

    return results