
import ast
from pathlib import Path

from scanner.context import build_rule_context, get_source_context
from scanner.finding import create_finding


HTTP_METHODS = {"get", "post", "request"}

REQUEST_INPUT_ATTRIBUTES = {
    "args",
    "form",
    "values",
    "json",
    "headers",
    "cookies",
    "data",
    "files",
}


def _is_request_input_attribute(node):
    """Return whether a node accesses a recognized request input source."""
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "request"
        and node.attr in REQUEST_INPUT_ATTRIBUTES
    )


def _is_untrusted_expression(node, untrusted_variables=None):
    """Check whether an expression contains or references untrusted input."""
    if untrusted_variables is None:
        untrusted_variables = set()

    if isinstance(node, ast.Name):
        return node.id in untrusted_variables

    if isinstance(node, ast.Call):
        # input("URL: ")
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return True

        # request.get_json()
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "request"
            and node.func.attr in {"get_json", "get_data"}
        ):
            return True

        # request.args.get("url"), request.headers.get("Host"), etc.
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and _is_request_input_attribute(node.func.value)
        ):
            return True

        # Propagate taint through wrappers, e.g. str(payload["url"]).
        return any(
            _is_untrusted_expression(arg, untrusted_variables)
            for arg in node.args
        ) or any(
            _is_untrusted_expression(keyword.value, untrusted_variables)
            for keyword in node.keywords
        )

    # request.json, request.headers, etc.
    if _is_request_input_attribute(node):
        return True

    # request.json["url"] or payload["url"] when payload is tainted.
    if isinstance(node, ast.Subscript):
        return _is_untrusted_expression(node.value, untrusted_variables)

    # Propagate through expressions such as url.strip() or url + suffix.
    if isinstance(node, ast.Attribute):
        return _is_untrusted_expression(node.value, untrusted_variables)

    if isinstance(node, ast.BinOp):
        return (
            _is_untrusted_expression(node.left, untrusted_variables)
            or _is_untrusted_expression(node.right, untrusted_variables)
        )

    if isinstance(node, (ast.JoinedStr, ast.List, ast.Tuple, ast.Set)):
        return any(
            _is_untrusted_expression(item, untrusted_variables)
            for item in node.values
            if isinstance(item, ast.expr)
        )

    if isinstance(node, ast.Dict):
        return any(
            _is_untrusted_expression(item, untrusted_variables)
            for item in [*node.keys, *node.values]
            if item is not None
        )

    return False


def _is_untrusted_variable(node, untrusted_variables):
    """Check whether an expression depends on a known untrusted source."""
    return _is_untrusted_expression(node, untrusted_variables)


def _propagate_untrusted_variables(tree):
    """Track untrusted values through simple assignments to a fixed point."""
    untrusted_variables = set()
    assignments = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue

        value = node.value
        if value is None:
            continue

        targets = node.targets if isinstance(node, ast.Assign) else [node.target]

        names = [
            target.id
            for target in targets
            if isinstance(target, ast.Name)
        ]

        if names:
            assignments.append((names, value))

    changed = True
    while changed:
        changed = False

        for targets, value in assignments:
            if _is_untrusted_expression(value, untrusted_variables):
                for name in targets:
                    if name not in untrusted_variables:
                        untrusted_variables.add(name)
                        changed = True

    return untrusted_variables


def _add_source_context(finding, context, line_number):
    """Add surrounding source-code context to a finding."""
    finding["source_context"] = get_source_context(context, line_number)
    return finding


def _get_url_argument(node, method_name):
    """Extract the URL argument from supported network calls."""
    if method_name == "request":
        # requests.request("GET", url)
        if len(node.args) >= 2:
            return node.args[1]

        for keyword in node.keywords:
            if keyword.arg == "url":
                return keyword.value

        return None

    # requests.get(url), requests.post(url)
    if node.args:
        return node.args[0]

    for keyword in node.keywords:
        if keyword.arg == "url":
            return keyword.value

    return None


def _is_supported_network_sink(node):
    """Return the URL argument for a supported network request."""
    func = node.func

    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "requests"
        and func.attr in HTTP_METHODS
    ):
        return _get_url_argument(node, func.attr)

    # urllib.request.urlopen(url), including url= and fullurl=.
    if isinstance(func, ast.Attribute) and func.attr == "urlopen":
        if node.args:
            return node.args[0]

        for keyword in node.keywords:
            if keyword.arg in {"url", "fullurl"}:
                return keyword.value

    return None


def detect_ssrf(source_code, file_name="unknown"):
    """
    Detect user-controlled values reaching supported network request sinks.

    Accepts raw Python source code or a path to a Python source file.
    """
    findings = []

    if not isinstance(source_code, (str, Path)):
        return findings

    # Support both source text and file paths.
    try:
        candidate_path = Path(source_code)
        if (
            isinstance(source_code, str)
            and "\n" not in source_code
            and "\r" not in source_code
            and candidate_path.is_file()
        ):
            file_name = str(candidate_path)
            source_code = candidate_path.read_text(encoding="utf-8")
    except (OSError, ValueError, TypeError):
        pass

    if not isinstance(source_code, str):
        return findings

    try:
        tree = ast.parse(source_code)
    except (SyntaxError, TypeError, ValueError):
        return findings

    try:
        context = build_rule_context(file_name)
    except (SyntaxError, ValueError, OSError, UnicodeError):
        context = {"lines": source_code.splitlines()}

    untrusted_variables = _propagate_untrusted_variables(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        url_arg = _is_supported_network_sink(node)
        if url_arg is None:
            continue

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
