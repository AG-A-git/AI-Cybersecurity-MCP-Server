# ======================================================
# Vulnerability Type Normalization
# ======================================================

from ai.vulnerability_mapping import VULNERABILITY_MAPPING


# ======================================================
# Alternative names -> canonical vulnerability names
# ======================================================

VULNERABILITY_ALIASES = {

    # --------------------------------------------------
    # SQL Injection
    # --------------------------------------------------

    "sqli": "SQL Injection",
    "sql injection": "SQL Injection",
    "sql injection vulnerability": "SQL Injection",

    # --------------------------------------------------
    # Cross-Site Scripting
    # --------------------------------------------------

    "xss": "XSS",
    "cross site scripting": "XSS",
    "cross-site scripting": "XSS",
    "cross site scripting vulnerability": "XSS",
    "cross-site scripting vulnerability": "XSS",

    # --------------------------------------------------
    # Command Injection
    # --------------------------------------------------

    "command injection": "Command Injection",
    "command injection vulnerability": "Command Injection",
    "os command injection": "Command Injection",
    "os command execution": "Command Injection",

    # --------------------------------------------------
    # LDAP Injection
    # --------------------------------------------------

    "ldap injection": "LDAP Injection",
    "ldap injection vulnerability": "LDAP Injection",

    # --------------------------------------------------
    # Hardcoded Credentials / Secrets
    # --------------------------------------------------

    "hardcoded credentials": "Hardcoded Credentials/Secrets",
    "hardcoded password": "Hardcoded Credentials/Secrets",
    "hardcoded secret": "Hardcoded Credentials/Secrets",
    "hardcoded secrets": "Hardcoded Credentials/Secrets",
    "hardcoded credentials/secrets": "Hardcoded Credentials/Secrets",
    "hardcoded credential": "Hardcoded Credentials/Secrets",

    # --------------------------------------------------
    # Weak Cryptography
    # --------------------------------------------------

    "weak cryptography": "Weak Cryptography",
    "weak encryption": "Weak Cryptography",
    "weak cryptographic algorithm": "Weak Cryptography",
    "weak crypto": "Weak Cryptography",

    # --------------------------------------------------
    # Broken Access Control
    # --------------------------------------------------

    "broken access control": "Broken Access Control",
    "access control vulnerability": "Broken Access Control",
    "broken authorization": "Broken Access Control",

    # --------------------------------------------------
    # Security Misconfiguration
    # --------------------------------------------------

    "security misconfiguration": "Security Misconfiguration",
    "misconfiguration": "Security Misconfiguration",
    "insecure configuration": "Security Misconfiguration",
    "security configuration issue": "Security Misconfiguration",

    # --------------------------------------------------
    # Insecure Authentication
    # --------------------------------------------------

    "insecure authentication": "Insecure Authentication",
    "authentication weakness": "Insecure Authentication",
    "weak authentication": "Insecure Authentication",
    "authentication vulnerability": "Insecure Authentication",

    # --------------------------------------------------
    # Insecure Deserialization
    # --------------------------------------------------

    "insecure deserialization": "Insecure Deserialization",
    "unsafe deserialization": "Insecure Deserialization",
    "deserialization vulnerability": "Insecure Deserialization",

    # --------------------------------------------------
    # Sensitive Data Exposure
    # --------------------------------------------------

    "sensitive data exposure": "Sensitive Data Exposure",
    "sensitive information exposure": "Sensitive Data Exposure",
    "data exposure": "Sensitive Data Exposure",
    "sensitive information disclosure": "Sensitive Data Exposure",

    # --------------------------------------------------
    # SSRF
    # --------------------------------------------------

    "ssrf": "SSRF",
    "server-side request forgery": "SSRF",
    "server side request forgery": "SSRF",
    "server-side request forgery vulnerability": "SSRF",
}


# ======================================================
# Normalize Vulnerability Type
# ======================================================

def normalize_vulnerability_type(value: str) -> str:
    """
    Convert a vulnerability name or alias into its
    canonical vulnerability name.

    Raises:
        ValueError:
            If the vulnerability type is invalid,
            empty, or unsupported.
    """

    # --------------------------------------------------
    # Validate input type
    # --------------------------------------------------

    if not isinstance(value, str):
        raise ValueError(
            "Vulnerability type must be a string."
        )

    # --------------------------------------------------
    # Normalize whitespace and capitalization
    # --------------------------------------------------

    normalized = value.strip().lower()

    if not normalized:
        raise ValueError(
            "Vulnerability type cannot be empty."
        )

    # --------------------------------------------------
    # Check canonical vulnerability names
    # --------------------------------------------------

    for canonical_name in VULNERABILITY_MAPPING:

        if normalized == canonical_name.lower():
            return canonical_name

    # --------------------------------------------------
    # Check aliases
    # --------------------------------------------------

    canonical_name = VULNERABILITY_ALIASES.get(
        normalized
    )

    if canonical_name:
        return canonical_name

    # --------------------------------------------------
    # Unknown vulnerability
    # --------------------------------------------------

    raise ValueError(
        f"Unknown vulnerability type: {value}"
    )