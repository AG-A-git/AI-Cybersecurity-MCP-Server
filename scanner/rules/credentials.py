import re

from scanner.finding import create_finding


# Credential-like variable names.
SECRET_NAMES = (
    r"password|passwd|pwd|secret|secret_key|api_key|apikey|"
    r"token|access_token|private_key|client_secret|"
    r"aws_secret_access_key"
)


# Detect credential-like variables assigned hardcoded strings.
HARDCODED_SECRET_PATTERN = re.compile(
    rf"\b({SECRET_NAMES})\b\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE
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
    """
    Detect potential hardcoded credentials and secrets.

    Only credential-like variable names assigned to
    suspicious hardcoded string values are reported.
    """

    results = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            lines = file.readlines()

    except (FileNotFoundError, OSError):
        return results

    for line_number, line in enumerate(lines, start=1):

        match = HARDCODED_SECRET_PATTERN.search(line)

        if not match:
            continue

        secret_value = match.group(2).strip()

        # Ignore empty values.
        if not secret_value:
            continue

        # Ignore obvious placeholder values.
        if secret_value.lower() in SAFE_VALUES:
            continue

        results.append(
            create_finding(
                file_name=file_path,
                line_number=line_number,
                vulnerability_type="Hardcoded Credentials / Secrets",
                severity="High",
                confidence=90,
                code=line.strip(),
                owasp="A07: Identification and Authentication Failures",
                cwe="CWE-798"
            )
        )

    return results