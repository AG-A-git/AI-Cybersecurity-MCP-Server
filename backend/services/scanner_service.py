
import ast
import re
from pathlib import Path


def scan_file(file_path: str) -> list[dict]:
    """
    Basic static security scanner for Python files.

    Detects:
    - Potential SQL injection
    - eval() usage
    - subprocess calls with shell=True
    - Hard-coded credential-like strings
    - Python syntax errors

    This is a demonstration scanner, not a replacement for
    comprehensive security analysis.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Uploaded file not found: {file_path}")

    if path.suffix.lower() != ".py":
        return []

    try:
        source = path.read_text(
            encoding="utf-8-sig",
            errors="replace",
        )
    except OSError as exc:
        raise RuntimeError(
            f"Unable to read file: {exc}"
        ) from exc

    findings = []
    seen_findings = set()

    def add_finding(
        line_number: int,
        vulnerability_type: str,
        severity: str,
        description: str,
        code_snippet: str = "",
    ) -> None:
        """Add a finding only once."""
        key = (
            line_number,
            vulnerability_type,
            severity,
            description,
        )

        if key in seen_findings:
            return

        seen_findings.add(key)

        findings.append({
            "line": line_number,
            "vulnerability": vulnerability_type,
            "severity": severity,
            "description": description,
            "code": code_snippet,
        })

    # Parse the source before applying AST-based checks.
    try:
        tree = ast.parse(source, filename=path.name)
    except SyntaxError as exc:
        add_finding(
            line_number=exc.lineno or 1,
            vulnerability_type="Python syntax error",
            severity="Info",
            description=(
                f"Unable to parse Python source: {exc.msg}"
            ),
            code_snippet="",
        )
        return findings

    # Detect potentially dangerous function calls.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Detect eval(...)
            if isinstance(node.func, ast.Name) and node.func.id == "eval":
                add_finding(
                    line_number=node.lineno,
                    vulnerability_type="Use of eval()",
                    severity="High",
                    description=(
                        "eval() can execute dynamically supplied "
                        "expressions and may enable code execution."
                    ),
                    code_snippet=ast.get_source_segment(source, node) or "",
                )

            # Detect subprocess calls with shell=True.
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {
                    "run",
                    "Popen",
                    "call",
                    "check_call",
                    "check_output",
                }
            ):
                shell_true = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )

                if shell_true:
                    add_finding(
                        line_number=node.lineno,
                        vulnerability_type="Subprocess shell=True",
                        severity="High",
                        description=(
                            "Using shell=True with subprocess may "
                            "allow command injection if input is "
                            "not safely controlled."
                        ),
                        code_snippet=(
                            ast.get_source_segment(source, node) or ""
                        ),
                    )

    # Detect potential hard-coded credentials and SQL injection
    # patterns using line-based checks.
    credential_pattern = re.compile(
        r"""(?i)\b(password|passwd|api_key|secret|token)\b"""
        r"""\s*=\s*['"][^'"]+['"]"""
    )

    sql_pattern = re.compile(
        r"""(?i)(execute|executemany)\s*\("""
        r""".*(%s|\+\s*\w+|\.format\s*\(|f['"])"""
    )

    for line_number, line in enumerate(
        source.splitlines(),
        start=1,
    ):
        if credential_pattern.search(line):
            add_finding(
                line_number=line_number,
                vulnerability_type="Possible hard-coded credential",
                severity="Medium",
                description=(
                    "A credential-like variable appears to contain "
                    "a hard-coded string. Verify that it is not a "
                    "real secret."
                ),
                code_snippet=line.strip(),
            )

        if sql_pattern.search(line):
            add_finding(
                line_number=line_number,
                vulnerability_type="Potential SQL injection",
                severity="High",
                description=(
                    "A SQL execution call may use dynamically "
                    "constructed SQL. Prefer parameterized queries."
                ),
                code_snippet=line.strip(),
            )

    findings.sort(
        key=lambda finding: (
            finding["line"],
            finding["vulnerability"],
        )
    )

    return findings


def run_scanner(file_path: str) -> list[dict]:
    """Run the scanner and normalize findings for the scan router."""
    findings = scan_file(file_path)
    file_name = Path(file_path).name

    normalized_findings = []

    for finding in findings:
        normalized = dict(finding)
        normalized["file"] = file_name
        normalized["confidence"] = normalized.get("confidence") or "Medium"
        normalized_findings.append(normalized)

    return normalized_findings
