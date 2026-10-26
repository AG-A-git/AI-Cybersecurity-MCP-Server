import ast

from scanner.context import build_rule_context, get_source_context
from scanner.finding import create_finding


def is_static_true_variable(context, variable_name):
    value = context.get("variables", {}).get(variable_name)
    return isinstance(value, str) and value.strip() == "True"

def scan_security_misconfiguration(file_path):
    """
    Detect clearly identifiable insecure Flask configuration.

    Current detection:
        app.run(debug=True)

    Severity:
        Medium

    Confidence:
        95

    Limitations:
        Variable-based debug configuration such as
        debug = True followed by app.run(debug=debug)
        is not currently detected.
    """

    results = []

    # ---------------------------------------------------------
    # Read source file
    # ---------------------------------------------------------

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            code = file.read()

    except (FileNotFoundError, OSError):
        return results

    # ---------------------------------------------------------
    # Parse Python AST
    # ---------------------------------------------------------

    try:
        tree = ast.parse(code)

    except SyntaxError:
        return results

    # ---------------------------------------------------------
    # Build shared rule context
    # ---------------------------------------------------------

    try:
        context = build_rule_context(file_path)

    except (
        SyntaxError,
        ValueError,
        OSError,
        UnicodeError
    ):
        context = {
            "lines": code.splitlines()
        }

    # ---------------------------------------------------------
    # Find app.run(debug=True)
    # ---------------------------------------------------------

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        function = node.func

        # Check for:
        #
        # app.run(...)
        #
        if not (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.attr == "run"
        ):
            continue

        # -----------------------------------------------------
        # Check keyword arguments
        # -----------------------------------------------------

        for keyword in node.keywords:

            if keyword.arg != "debug":
                continue

            # Detect explicit debug=True or a variable that is
            # statically assigned the value True.
            is_debug_enabled = (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            )

            if (
                isinstance(keyword.value, ast.Name)
                and is_static_true_variable(
                    context,
                    keyword.value.id,
                )
            ):
                is_debug_enabled = True

            if is_debug_enabled:

                code_line = code.splitlines()[node.lineno - 1].strip()

                finding = create_finding(
                    file_name=file_path,
                    line_number=node.lineno,
                    vulnerability_type="Security Misconfiguration",
                    severity="Medium",
                    confidence=95,
                    code=code_line,
                    owasp="A05: Security Misconfiguration",
                    cwe="CWE-489"
                )

                finding["source_context"] = get_source_context(
                    context,
                    node.lineno
                )

                results.append(finding)

    return results
