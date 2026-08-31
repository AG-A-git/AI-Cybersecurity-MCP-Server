# ======================================================
# Vulnerability Type Normalization
# ======================================================

from ai.vulnerability_mapping import VULNERABILITY_MAPPING


# Alternative names → canonical vulnerability names
VULNERABILITY_ALIASES = {
    # SQL Injection
    "sqli": "SQL Injection",
    "sql injection vulnerability": "SQL Injection",
    "sql injection": "SQL Injection",

    # XSS
    "xss": "XSS",
    "cross site scripting": "XSS",
    "cross-site scripting": "XSS",
    "cross site scripting vulnerability": "XSS",

    # Command Injection
    "command injection": "Command Injection",
    "os command injection": "Command Injection",
    "os command execution": "Command Injection",

    # LDAP Injection
    "ldap injection": "LDAP Injection",
    "ldap injection vulnerability": "LDAP Injection",

    # Hardcoded Credentials/Secrets
    "hardcoded credentials": "Hardcoded Credentials/Secrets",
    "hardcoded password": "Hardcoded Credentials/Secrets",
    "hardcoded secret": "Hardcoded Credentials/Secrets",
    "hardcoded secrets": "Hardcoded Credentials/Secrets",
    "hardcoded credentials/secrets": "Hardcoded Credentials/Secrets",

    # Weak Cryptography
    "weak cryptography": "Weak Cryptography",
    "weak encryption": "Weak Cryptography",
    "weak cryptographic algorithm": "Weak Cryptography",

    # Broken Access Control
    "broken access control": "Broken Access Control",
    "access control vulnerability": "Broken Access Control",

    # Security Misconfiguration
    "security misconfiguration": "Security Misconfiguration",
    "misconfiguration": "Security Misconfiguration",
    "insecure configuration": "Security Misconfiguration",

    # Insecure Authentication
    "insecure authentication": "Insecure Authentication",
    "authentication weakness": "Insecure Authentication",
    "weak authentication": "Insecure Authentication",

    # Insecure Deserialization
    "insecure deserialization": "Insecure Deserialization",
    "unsafe deserialization": "Insecure Deserialization",

    # Sensitive Data Exposure
    "sensitive data exposure": "Sensitive Data Exposure",
    "sensitive information exposure": "Sensitive Data Exposure",
    "data exposure": "Sensitive Data Exposure",

    # SSRF
    "ssrf": "SSRF",
    "server-side request forgery": "SSRF",
    "server side request forgery": "SSRF",
}


def normalize_vulnerability_type(value: str) -> str:
    """
    Convert a vulnerability name into its canonical name.

    Raises:
        ValueError: If the vulnerability type is unknown.
    """

    if not isinstance(value, str):
        raise ValueError("Vulnerability type must be a string.")

    normalized = value.strip().lower()

    if not normalized:
        raise ValueError("Vulnerability type cannot be empty.")

    # Direct canonical-name match
    for canonical_name in VULNERABILITY_MAPPING:
        if normalized == canonical_name.lower():
            return canonical_name

    # Alias match
    canonical_name = VULNERABILITY_ALIASES.get(normalized)

    if canonical_name:
        return canonical_name

    raise ValueError(
        f"Unknown vulnerability type: {value}"
    )