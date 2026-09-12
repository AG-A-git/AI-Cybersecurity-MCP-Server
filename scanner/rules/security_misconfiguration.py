import ast

from scanner.finding import create_finding


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

            # Only detect explicit:
            #
            # debug=True
            #
            if (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):

                code_line = code.splitlines()[node.lineno - 1].strip()

                results.append(
                    create_finding(
                        file_name=file_path,
                        line_number=node.lineno,
                        vulnerability_type="Security Misconfiguration",
                        severity="Medium",
                        confidence=95,
                        code=code_line,
                        owasp="A05: Security Misconfiguration",
                        cwe="CWE-489"
                    )
                )

    return results