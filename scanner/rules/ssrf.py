
import ast
from pathlib import Path

from scanner.finding import create_finding


HTTP_METHODS = {"get", "post", "request"}


def _is_untrusted_expression(node):
    """Check whether an expression comes directly from user input."""

    # input("...")
    if isinstance(node, ast.Call):

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "input"
        ):
            return True

        # request.args.get(...)
        # request.form.get(...)
        # request.values.get(...)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "request"
            and node.func.value.attr in {
                "args",
                "form",
                "values"
            }
        ):
            return True

    return False


def _is_untrusted_variable(node, untrusted_variables):
    """Check whether an expression is a known untrusted variable."""

    return (
        isinstance(node, ast.Name)
        and node.id in untrusted_variables
    )


def detect_ssrf(source_code, file_name="unknown"):
    """
    Detect Server-Side Request Forgery (SSRF).

    Supports both:
        1. Raw source code
        2. A file path

    User-controlled URLs are detected when passed to:
        - requests.get()
        - requests.post()
        - requests.request()
        - urllib.request.urlopen()
    """

    findings = []

    # Support both raw source code and a file path.
    if Path(source_code).is_file():
        file_path = Path(source_code)
        file_name = str(file_path)
        source_code = file_path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(source_code)

    except SyntaxError:
        return findings

    untrusted_variables = set()

    # ------------------------------------------------------------
    # Find variables that receive user-controlled input.
    # ------------------------------------------------------------

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            if _is_untrusted_expression(node.value):

                for target in node.targets:

                    if isinstance(target, ast.Name):
                        untrusted_variables.add(target.id)

    # ------------------------------------------------------------
    # Find HTTP requests using untrusted variables.
    # ------------------------------------------------------------

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        func = node.func

        # --------------------------------------------------------
        # requests.get(...)
        # requests.post(...)
        # requests.request(...)
        # --------------------------------------------------------

        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "requests"
            and func.attr in HTTP_METHODS
        ):

            if func.attr == "request":

                # requests.request("GET", url)
                if len(node.args) >= 2:
                    url_arg = node.args[1]
                else:
                    continue

            else:

                # requests.get(url)
                # requests.post(url)
                if not node.args:
                    continue

                url_arg = node.args[0]

            if _is_untrusted_variable(
                url_arg,
                untrusted_variables
            ):

                code_line = (
                    ast.get_source_segment(
                        source_code,
                        node
                    )
                    or ""
                )

                findings.append(
                    create_finding(
                        vulnerability_type="SSRF",
                        file_name=file_name,
                        line_number=node.lineno,
                        severity="High",
                        confidence=90,
                        code=code_line,
                        owasp="A10: Server-Side Request Forgery",
                        cwe="CWE-918"
                    )
                )

        # --------------------------------------------------------
        # urllib.request.urlopen(...)
        # --------------------------------------------------------

        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "urlopen"
        ):

            if not node.args:
                continue

            url_arg = node.args[0]

            if _is_untrusted_variable(
                url_arg,
                untrusted_variables
            ):

                code_line = (
                    ast.get_source_segment(
                        source_code,
                        node
                    )
                    or ""
                )

                findings.append(
                    create_finding(
                        vulnerability_type="SSRF",
                        file_name=file_name,
                        line_number=node.lineno,
                        severity="High",
                        confidence=90,
                        code=code_line,
                        owasp="A10: Server-Side Request Forgery",
                        cwe="CWE-918"
                    )
                )

    return findings
