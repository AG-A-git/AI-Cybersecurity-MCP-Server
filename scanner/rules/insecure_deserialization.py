import ast

from scanner.finding import create_finding


UNTRUSTED_SOURCES = {
    "request.data",
    "request.form",
    "request.args",
    "request.values",
    "request.json",
    "request.files",
}


def is_untrusted_expression(node):
    """Check whether an AST expression represents untrusted input."""

    # input()
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id == "input"

    # request.data, request.form, request.args, etc.
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            expression = f"{node.value.id}.{node.attr}"
            return expression in UNTRUSTED_SOURCES

    # request.files["data"]
    if isinstance(node, ast.Subscript):
        value = node.value

        if (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "request"
            and value.attr == "files"
        ):
            return True

    return False


def scan_insecure_deserialization(file_path):
    """
    Detect insecure Python pickle deserialization.

    High confidence (90):
        Untrusted input -> pickle.load/load

    Lower confidence (75):
        pickle.load/loads with unknown input.
    """

    results = []

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

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return results

    tainted_variables = set()

    # ---------------------------------------------------------
    # Pass 1:
    # Find variables containing untrusted input.
    # ---------------------------------------------------------

    for node in ast.walk(tree):

        if not isinstance(node, ast.Assign):
            continue

        if not node.targets:
            continue

        if not is_untrusted_expression(node.value):
            continue

        for target in node.targets:

            if isinstance(target, ast.Name):
                tainted_variables.add(target.id)

    # ---------------------------------------------------------
    # Pass 2:
    # Find pickle.load() / pickle.loads()
    # ---------------------------------------------------------

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        function = node.func

        if not (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id == "pickle"
            and function.attr in {"load", "loads"}
        ):
            continue

        confidence = 75

        if node.args:
            argument = node.args[0]

            # Direct untrusted input
            if is_untrusted_expression(argument):
                confidence = 90

            # Tainted variable
            elif (
                isinstance(argument, ast.Name)
                and argument.id in tainted_variables
            ):
                confidence = 90

        code_line = code.splitlines()[node.lineno - 1].strip()

        results.append(
            create_finding(
                file_name=file_path,
                line_number=node.lineno,
                vulnerability_type="Insecure Deserialization",
                severity="High",
                confidence=confidence,
                code=code_line,
                owasp="A08: Software and Data Integrity Failures",
                cwe="CWE-502"
            )
        )

    return results