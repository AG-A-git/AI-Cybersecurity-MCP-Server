
import os
import re


def scan_project(project_path):
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
                with open(file_path, "r", encoding="utf-8") as file:
                    lines = file.readlines()
            except (OSError, UnicodeDecodeError):
                continue

            # Detect SQL f-strings spanning multiple source lines.
            source_text = "".join(lines)
            multiline_pattern = r"(?is)\bf(?P<quote>\x27{3}|\x22{3})(?:(?!(?P=quote)).)*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:(?!(?P=quote)).)*?\{[^{}]+\}(?:(?!(?P=quote)).)*?(?P=quote)"
            for match in re.finditer(multiline_pattern, source_text):
                matched_code = match.group(0)
                if "\n" not in matched_code:
                    continue
                start_line = source_text.count("\n", 0, match.start()) + 1
                findings.append(
                    {
                        "file": os.path.relpath(file_path, project_path),
                        "line": start_line,
                        "vulnerability": "SQL Injection",
                        "severity": "Critical",
                        "confidence": 95,
                        "code": matched_code.strip(),
                    }
                )

            for line_number, line in enumerate(lines, start=1):
                stripped_line = line.strip()

                # SQL Injection detection
                sql_injection = (
                    re.search(
                        r"\.execute\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
                        stripped_line,
                    )
                    or re.search(
                        r"""["']SELECT\b.*["']\s*\+\s*[A-Za-z_][A-Za-z0-9_]*""",
                        stripped_line,
                        re.IGNORECASE,
                    )
                    or re.search(
                        r"""["'].*\bWHERE\b.*["']\s*\+\s*[A-Za-z_][A-Za-z0-9_]*""",
                        stripped_line,
                        re.IGNORECASE,
                    )
                    # Detect common SQL statements using Python f-strings
                    or re.search(
                        r"""(?i)\bf["'].*\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\{[^{}]+\}.*["']""",
                        stripped_line,
                    )
                )

                if sql_injection:
                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path, project_path
                            ),
                            "line": line_number,
                            "vulnerability": "SQL Injection",
                            "severity": "Critical",
                            "confidence": 95,
                            "code": stripped_line,
                        }
                    )
                    continue

                # Hardcoded credential detection
                hardcoded_credential = re.search(
                    r"""^\s*(password|passwd|pwd|secret|api_key|apikey)\s*=\s*["'][^"']+["']""",
                    stripped_line,
                    re.IGNORECASE,
                )

                if hardcoded_credential:
                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path, project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Hardcoded Credentials",
                            "severity": "High",
                            "confidence": 95,
                            "code": stripped_line,
                        }
                    )

                # Python eval() detection
                if re.search(r"\beval\s*\(", stripped_line):
                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path, project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Code Injection",
                            "severity": "High",
                            "confidence": 90,
                            "code": stripped_line,
                        }
                    )

                # os.system() command injection detection
                if re.search(r"\bos\.system\s*\(", stripped_line):
                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path, project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Command Injection",
                            "severity": "High",
                            "confidence": 90,
                            "code": stripped_line,
                        }
                    )

                # subprocess shell=True command injection detection
                if (
                    "subprocess." in stripped_line
                    and "shell=True" in stripped_line
                ):
                    findings.append(
                        {
                            "file": os.path.relpath(
                                file_path, project_path
                            ),
                            "line": line_number,
                            "vulnerability": "Command Injection",
                            "severity": "High",
                            "confidence": 90,
                            "code": stripped_line,
                        }
                    )

    return findings
