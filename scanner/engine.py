
import os
import re
import time


DEFAULT_MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1 MiB
DEFAULT_MAX_FILES = 10_000
DEFAULT_TIMEOUT_SECONDS = 60.0


def scan_project(
    project_path,
    *,
    max_file_size_bytes=DEFAULT_MAX_FILE_SIZE_BYTES,
    max_files=DEFAULT_MAX_FILES,
    timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
):
    """Scan Python files while enforcing basic resource limits.

    Files exceeding the size limit are skipped. Scanning stops when the
    file-count or duration limit is reached. Results can be partial when
    a project exceeds either limit.

    The timeout is best-effort: it is checked between operations and
    cannot interrupt an ongoing blocking file read or regex operation.
    """
    if max_file_size_bytes < 0:
        raise ValueError("max_file_size_bytes must be non-negative")
    if max_files < 0:
        raise ValueError("max_files must be non-negative")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    if not os.path.isdir(project_path):
        raise FileNotFoundError(
            f"Project path does not exist: {project_path}"
        )

    findings = []
    started_at = time.monotonic()
    project_root = os.path.realpath(project_path)
    files_considered = 0

    multiline_pattern = (
        r"(?is)\bf(?P<quote>\x27{3}|\x22{3})"
        r"(?:(?!(?P=quote)).)*?"
        r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b"
        r"(?:(?!(?P=quote)).)*?"
        r"\{[^{}]+\}"
        r"(?:(?!(?P=quote)).)*?(?P=quote)"
    )

    def time_limit_reached():
        return time.monotonic() - started_at >= timeout_seconds

    def add_finding(
        relative_path,
        line_number,
        vulnerability,
        severity,
        confidence,
        code,
    ):
        findings.append(
            {
                "file": relative_path,
                "line": line_number,
                "vulnerability": vulnerability,
                "severity": severity,
                "confidence": confidence,
                "code": code,
            }
        )

    for root, dirs, files in os.walk(
        project_root,
        followlinks=False,
    ):
        if time_limit_reached() or files_considered >= max_files:
            break

        # Do not traverse symlinked directories.
        dirs[:] = [
            dirname
            for dirname in dirs
            if not os.path.islink(os.path.join(root, dirname))
        ]

        for filename in files:
            if time_limit_reached() or files_considered >= max_files:
                break

            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(root, filename)

            # Skip symlinked files.
            if os.path.islink(file_path):
                continue

            # Ensure the resolved file remains inside the project root.
            resolved_file = os.path.realpath(file_path)
            try:
                if (
                    os.path.commonpath(
                        [project_root, resolved_file]
                    )
                    != project_root
                ):
                    continue
            except ValueError:
                continue

            try:
                # Check size before loading file contents.
                if (
                    os.path.getsize(resolved_file)
                    > max_file_size_bytes
                ):
                    files_considered += 1
                    continue

                with open(
                    resolved_file,
                    "r",
                    encoding="utf-8",
                ) as file:
                    lines = file.readlines()

            except (OSError, UnicodeDecodeError):
                # Unreadable Python files still consume the file budget.
                files_considered += 1
                continue

            files_considered += 1

            relative_path = os.path.relpath(
                resolved_file,
                project_root,
            )
            source_text = "".join(lines)

            # Detect SQL f-strings spanning multiple source lines.
            for match in re.finditer(
                multiline_pattern,
                source_text,
            ):
                if time_limit_reached():
                    return findings

                matched_code = match.group(0)

                if "\n" not in matched_code:
                    continue

                start_line = (
                    source_text.count("\n", 0, match.start()) + 1
                )

                add_finding(
                    relative_path,
                    start_line,
                    "SQL Injection",
                    "Critical",
                    95,
                    matched_code.strip(),
                )

            for line_number, line in enumerate(lines, start=1):
                if time_limit_reached():
                    return findings

                stripped_line = line.strip()

                # SQL Injection detection.
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
                    or re.search(
                        r"""(?i)\bf["'].*\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\{[^{}]+\}.*["']""",
                        stripped_line,
                    )
                )

                if sql_injection:
                    add_finding(
                        relative_path,
                        line_number,
                        "SQL Injection",
                        "Critical",
                        95,
                        stripped_line,
                    )
                    continue

                # Hardcoded credential detection.
                hardcoded_credential = re.search(
                    r"""^\s*(password|passwd|pwd|secret|api_key|apikey)\s*=\s*["'][^"']+["']""",
                    stripped_line,
                )

                if hardcoded_credential:
                    add_finding(
                        relative_path,
                        line_number,
                        "Hardcoded Credentials",
                        "High",
                        95,
                        stripped_line,
                    )

                # Python eval() detection.
                if re.search(r"\beval\s*\(", stripped_line):
                    add_finding(
                        relative_path,
                        line_number,
                        "Code Injection",
                        "High",
                        90,
                        stripped_line,
                    )

                # os.system() command injection detection.
                if re.search(r"\bos\.system\s*\(", stripped_line):
                    add_finding(
                        relative_path,
                        line_number,
                        "Command Injection",
                        "High",
                        90,
                        stripped_line,
                    )

                # subprocess shell=True command injection detection.
                if (
                    "subprocess." in stripped_line
                    and "shell=True" in stripped_line
                ):
                    add_finding(
                        relative_path,
                        line_number,
                        "Command Injection",
                        "High",
                        90,
                        stripped_line,
                    )

    return findings
