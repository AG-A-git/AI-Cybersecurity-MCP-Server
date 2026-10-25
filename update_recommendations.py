
from pathlib import Path
import ast

file_path = Path("ai/prompts.py")
source = file_path.read_text(encoding="utf-8")

replacement = '''def get_recommendation(vulnerability):
    """Return actionable remediation advice for a vulnerability type."""
    fallback = (
        "Validate the finding, identify its root cause, apply appropriate "
        "security controls, and add a regression test."
    )

    if not isinstance(vulnerability, str) or not vulnerability.strip():
        return fallback

    normalized = (
        vulnerability.strip()
        .lower()
        .replace("_", " ")
        .replace("-", " ")
    )

    if "sql injection" in normalized or normalized == "sqli":
        return (
            "Use parameterized queries or prepared statements. "
            "Never concatenate untrusted input into SQL queries."
        )

    if normalized == "xss" or "cross site scripting" in normalized:
        return (
            "Apply context-appropriate output encoding and safely handle "
            "untrusted input. Avoid unsafe DOM operations."
        )

    if "command injection" in normalized or "os command execution" in normalized:
        return (
            "Avoid passing untrusted input to operating-system commands. "
            "Prefer safe library APIs and strict input validation."
        )

    if "ldap injection" in normalized:
        return (
            "Use safe LDAP query APIs, correctly escape special characters, "
            "and validate untrusted input before building LDAP queries."
        )

    if "hardcoded credential" in normalized or "hardcoded secret" in normalized:
        return (
            "Remove secrets from source code, rotate exposed credentials, "
            "and use a secure secrets manager."
        )

    if "hardcoded password" in normalized:
        return (
            "Remove hardcoded passwords, rotate exposed credentials, "
            "and retrieve secrets from a secure secrets manager."
        )

    if "weak cryptography" in normalized or "weak encryption" in normalized or normalized == "weak crypto":
        return (
            "Replace deprecated algorithms and weak configurations with "
            "approved cryptographic algorithms and secure key management."
        )

    if "broken access control" in normalized or "broken authorization" in normalized:
        return (
            "Enforce server-side authorization for protected resources and "
            "actions. Apply least privilege and test cross-user access."
        )

    if "security misconfiguration" in normalized or normalized == "misconfiguration" or normalized == "insecure configuration":
        return (
            "Apply secure configuration defaults, disable unnecessary "
            "services and debug features, remove default credentials, "
            "and verify settings against a security baseline."
        )

    if "insecure authentication" in normalized or "authentication weakness" in normalized or "weak authentication" in normalized or "authentication vulnerability" in normalized:
        return (
            "Use a maintained authentication framework, protect passwords "
            "and sessions, apply rate limiting, and use multi-factor "
            "authentication where appropriate."
        )

    if "insecure deserialization" in normalized or "unsafe deserialization" in normalized or "deserialization vulnerability" in normalized:
        return (
            "Avoid deserializing untrusted data where possible. Use safe "
            "data formats, restrict accepted types, and validate data."
        )

    if (
        "sensitive data exposure" in normalized
        or "sensitive information exposure" in normalized
        or "sensitive information disclosure" in normalized
        or "data exposure" in normalized
    ):
        return (
            "Minimize sensitive data storage, enforce least-privilege access, "
            "protect data in transit and at rest, and redact secrets from logs."
        )

    if normalized == "ssrf" or "server side request forgery" in normalized:
        return (
            "Restrict outbound requests to approved destinations, validate "
            "URLs and resolved IP addresses, block internal and metadata "
            "endpoints, and enforce network egress controls."
        )

    if "path traversal" in normalized:
        return (
            "Normalize and validate file paths, restrict access to an "
            "approved base directory, and reject paths outside it."
        )

    return fallback
'''

tree = ast.parse(source)
matches = [
    node for node in tree.body
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    and node.name == "get_recommendation"
]

if len(matches) != 1:
    raise RuntimeError(
        f"Expected exactly one get_recommendation function; found {len(matches)}"
    )

function = matches[0]
lines = source.splitlines(keepends=True)
start = function.lineno - 1
end = function.end_lineno

updated = "".join(lines[:start]) + replacement + "\n\n" + "".join(lines[end:])

# Validate Python syntax before writing.
ast.parse(updated)

# Create a backup before modifying the original file.
backup_path = file_path.with_suffix(".py.task7-backup")
backup_path.write_text(source, encoding="utf-8")
file_path.write_text(updated, encoding="utf-8")

print("Updated get_recommendation() successfully.")
print(f"Backup created: {backup_path}")
