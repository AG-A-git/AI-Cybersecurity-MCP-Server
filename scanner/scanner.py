"""
Project Security Scanner

Scans Python, HTML, JavaScript and configuration files
for common security vulnerabilities.
"""

from pathlib import Path
import re


# ======================================================
# Vulnerability Rules
# ======================================================

RULES = [
    {
        "vulnerability": "SQL Injection",
        "severity": "High",
        "patterns": [
            r"\.execute\s*\(\s*[^'\"]",
            r"\.execute\s*\(\s*f['\"]",
            r"execute\s*\([^)]*\+",
            r"SELECT\s+.*\+",
            r"SELECT\s+.*f['\"]",
        ],
    },
    {
        "vulnerability": "XSS",
        "severity": "Medium",
        "patterns": [
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"document\.write\s*\(",
        ],
    },
    {
        "vulnerability": "Command Injection",
        "severity": "High",
        "patterns": [
            r"os\.system\s*\(",
            r"subprocess\.call\s*\(",
            r"subprocess\.run\s*\(",
            r"subprocess\.Popen\s*\(",
        ],
    },
    {
        "vulnerability": "Hardcoded Credentials/Secrets",
        "severity": "High",
        "patterns": [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"passwd\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"apikey\s*=\s*['\"][^'\"]+['\"]",
            r"token\s*=\s*['\"][^'\"]+['\"]",
        ],
    },
    {
        "vulnerability": "Weak Cryptography",
        "severity": "Medium",
        "patterns": [
            r"\bmd5\s*\(",
            r"\bsha1\s*\(",
            r"hashlib\.md5",
            r"hashlib\.sha1",
        ],
    },
    {
        "vulnerability": "Insecure Authentication",
        "severity": "High",
        "patterns": [
            r"verify\s*=\s*False",
            r"ssl_verify\s*=\s*False",
            r"check_hostname\s*=\s*False",
        ],
    },
    {
        "vulnerability": "Security Misconfiguration",
        "severity": "Medium",
        "patterns": [
            r"DEBUG\s*=\s*True",
            r"debug\s*=\s*True",
            r"allow_origins\s*=\s*\[\s*['\"]\*['\"]",
        ],
    },
    {
        "vulnerability": "SSRF",
        "severity": "High",
        "patterns": [
            r"requests\.get\s*\(",
            r"requests\.post\s*\(",
            r"urllib\.request",
            r"httpx\.get\s*\(",
        ],
    },
]


# ======================================================
# Supported Files
# ======================================================

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".htm",
    ".php",
    ".java",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
}


# ======================================================
# Ignored Directories
# ======================================================

IGNORED_DIRECTORIES = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    "venv",
    ".venv",
    "node_modules",
    "site-packages",
    "dist",
    "build",
}


# ======================================================
# Calculate Confidence
# ======================================================

def calculate_confidence(match_count: int) -> float:
    """
    Calculate scanner confidence.
    """

    confidence = 70 + (match_count * 5)

    return min(float(confidence), 100.0)


# ======================================================
# Scan One File
# ======================================================

def scan_file(file_path: Path) -> list[dict]:
    """
    Scan one source file.
    """

    findings = []

    try:
        content = file_path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except (OSError, UnicodeError):
        return findings

    lines = content.splitlines()

    for rule in RULES:

        for pattern in rule["patterns"]:

            try:
                regex = re.compile(
                    pattern,
                    re.IGNORECASE
                )

            except re.error:
                continue

            matches = list(
                regex.finditer(content)
            )

            if not matches:
                continue

            for match in matches:

                line_number = (
                    content.count(
                        "\n",
                        0,
                        match.start()
                    ) + 1
                )

                line_code = (
                    lines[line_number - 1].strip()
                    if 0 < line_number <= len(lines)
                    else ""
                )

                findings.append(
                    {
                        "file": str(file_path),
                        "line": line_number,
                        "vulnerability": rule[
                            "vulnerability"
                        ],
                        "severity": rule[
                            "severity"
                        ],
                        "confidence": calculate_confidence(
                            len(matches)
                        ),
                        "code": line_code,
                    }
                )

    return findings


# ======================================================
# Scan Project
# ======================================================

def scan_project(project_path: str = ".") -> list[dict]:
    """
    Scan a complete project directory.

    Returns a list of vulnerability findings.
    """

    root = Path(project_path).resolve()

    if not root.exists():
        raise FileNotFoundError(
            f"Project path does not exist: {project_path}"
        )

    if root.is_file():
        return scan_file(root)

    findings = []

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue

        if any(
            ignored in file_path.parts
            for ignored in IGNORED_DIRECTORIES
        ):
            continue

        if (
            file_path.suffix.lower()
            not in SUPPORTED_EXTENSIONS
        ):
            continue

        file_findings = scan_file(
            file_path
        )

        findings.extend(
            file_findings
        )

    return findings