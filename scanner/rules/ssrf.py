
import ast
from pathlib import Path

from scanner.context import build_rule_context, get_source_context
from scanner.finding import create_finding


HTTP_METHODS = {"get", "post", "request"}


def _is_untrusted_expression(node):
    """Check whether an expression comes directly from user input."""
    if isinstance(node, ast.Call):
        # input("...")
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return True

        # request.args.get(...), request.form.get(...), request.values.get(...)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "request"
            and node.func.value.attr in {"args", "form", "values"}
        ):
            return True

    return False


def _is_untrusted_variable(node, untrusted_variables):
    """Check whether an expression references a known untrusted variable."""
    return isinstance(node, ast.Name) and node.id in untrusted_variables


def _propagate_untrusted_variables(tree):
    """Track user-controlled values through chains of simple assignments."""
    untrusted_variables = set()
    assignments = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)

        if targets:
            assignments.append((targets, node.value))

    changed = True
    while changed:
        changed = False

        for targets, value in assignments:
            is_untrusted = _is_untrusted_expression(value)

            if (
                not is_untrusted
                and isinstance(value, ast.Name)
                and value.id in untrusted_variables
            ):
                is_untrusted = True

            if is_untrusted:
                for target_name in targets:
                    if target_name not in untrusted_variables:
                        untrusted_variables.add(target_name)
                        changed = True

    return untrusted_variables


def _add_source_context(finding, context, line_number):
    """Add surrounding source-code context to a finding."""
    finding["source_context"] = get_source_context(context, line_number)
    return finding


def detect_ssrf(source_code, file_name="unknown"):
    """
    Detect SSRF when user-controlled URLs reach supported network sinks.

    Accepts either raw source code or a path to a source file.
    """
    findings = []

    # Support both raw source code and a file path.
    try:
        candidate_path = Path(source_code)
        if "\n" not in source_code and "\r" not in source_code and candidate_path.is_file():
            file_name = str(candidate_path)
            source_code = candidate_path.read_text(encoding="utf-8")
    except (OSError, ValueError, TypeError):
        pass

    try:
        tree = ast.parse(source_code)
    except (SyntaxError, TypeError):
        return findings

    try:
        context = build_rule_context(file_name)
    except (SyntaxError, ValueError, OSError, UnicodeError):
        context = {"lines": source_code.splitlines()}

    untrusted_variables = _propagate_untrusted_variables(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        url_arg = None

        # requests.get(url), requests.post(url), requests.request("GET", url)
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "requests"
            and func.attr in HTTP_METHODS
        ):
            if func.attr == "request":
                if len(node.args) >= 2:
                    url_arg = node.args[1]
                else:
                    # Support requests.request(method="GET", url=url)
                    for keyword in node.keywords:
                        if keyword.arg == "url":
                            url_arg = keyword.value
                            break
            elif node.args:
                url_arg = node.args[0]
            else:
                # Support requests.get(url=url)
                for keyword in node.keywords:
                    if keyword.arg == "url":
                        url_arg = keyword.value
                        break

        # urllib.request.urlopen(url)
        elif isinstance(func, ast.Attribute) and func.attr == "urlopen":
            if node.args:
                url_arg = node.args[0]
            else:
                for keyword in node.keywords:
                    if keyword.arg in {"url", "fullurl"}:
                        url_arg = keyword.value
                        break

        if url_arg is None:
            continue

        # Only flag values proven to derive from recognized user input.
        if not _is_untrusted_variable(url_arg, untrusted_variables):
            continue

        code_line = ast.get_source_segment(source_code, node) or ""

        finding = create_finding(
            vulnerability_type="SSRF",
            file_name=file_name,
            line_number=node.lineno,
            severity="High",
            confidence=90,
            code=code_line,
            owasp="A10: Server-Side Request Forgery",
            cwe="CWE-918",
        )

        findings.append(
            _add_source_context(finding, context, node.lineno)
        )

    return findings