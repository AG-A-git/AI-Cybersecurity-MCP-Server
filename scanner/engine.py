import os
import re


def scan_project(project_path):
    """
    Scan a project directory for common security vulnerabilities.

    Returns:
        List of vulnerability dictionaries compatible with
        VulnerabilityInput.
    """

    findings = []

    if not os.path.isdir(project_path):
        raise FileNotFoundError(
            f"Project path does not exist: {project_path}"
        )

    for root, _, files in os.walk(project_path):

        for filename in files:

            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(root, filename)

            try:
                with open(
                    file_path,
                    "r",
                    encoding="utf-8"
                ) as file:
                    lines = file.readlines()

            except (OSError, UnicodeDecodeError):
                continue

            for line_number, line in enumerate(
                lines,
                start=1
            ):

                stripped_line = line.strip()

                # ==================================================
                # SQL Injection
                # ==================================================

                sql_injection = (
                    re.search(
                        r"\.execute\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
                        stripped_line
                    )
                    or
                    re.search(
                        r"""["']SELECT\b.*["']\s*\+\s*[A-Za-z_][A-Za-z0-9_]*""",
                        stripped_line,
                        re.IGNORECASE
                    )
                    or
                    re.search(
                        r"""["'].*\bWHERE\b.*["']\s*\+\s*[A-Za-z_][A-Za-z0-9_]*""",
                        stripped_line,
                        re.IGNORECASE
                    )
                )

                if sql_injection:

                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path,
                                project_path
                            ),
                            "line": line_number,
                            "vulnerability": "SQL Injection",
                            "severity": "Critical",
                            "confidence": 95,
                            "code": stripped_line
                        }
                    )

                    continue

                # ==================================================
                # Hardcoded Credentials
                # ==================================================

                hardcoded_credential = re.search(
                    r"^\s*(password|passwd|pwd|secret|api_key|apikey)"
                    r"\s*=\s*[\"'][^\"']+[\"']",
                    stripped_line,
                    re.IGNORECASE
                )

                if hardcoded_credential:

                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path,
                                project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Hardcoded Credentials",
                            "severity": "High",
                            "confidence": 95,
                            "code": stripped_line
                        }
                    )

                    continue

                # ==================================================
                # Code Injection - eval()
                # ==================================================

                if re.search(
                    r"\beval\s*\(",
                    stripped_line
                ):

                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path,
                                project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Code Injection",
                            "severity": "High",
                            "confidence": 90,
                            "code": stripped_line
                        }
                    )

                    continue

                # ==================================================
                # Command Injection - os.system()
                # ==================================================

                if re.search(
                    r"\bos\.system\s*\(",
                    stripped_line
                ):

                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path,
                                project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Command Injection",
                            "severity": "High",
                            "confidence": 90,
                            "code": stripped_line
                        }
                    )

                    continue

                # ==================================================
                # Command Injection - subprocess shell=True
                # ==================================================

                if (
                    "subprocess." in stripped_line
                    and "shell=True" in stripped_line
                ):

                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path,
                                project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Command Injection",
                            "severity": "High",
                            "confidence": 90,
                            "code": stripped_line
                        }
                    )

    return findings