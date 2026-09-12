import ast

from scanner.finding import create_finding


USER_INPUT_METHODS = {
    "args.get",
    "form.get",
    "values.get",
    "json.get",
}


def is_user_input(node):
    """
    Check whether an AST node represents a supported
    user-controlled input source.
    """

    # input(...)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id == "input":
                return True

        # request.args.get(...)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr != "get":
                return False

            if isinstance(node.func.value, ast.Attribute):
                request_obj = node.func.value

                if (
                    isinstance(request_obj.value, ast.Name)
                    and request_obj.value.id == "request"
                ):
                    source = f"{request_obj.attr}.get"

                    if source in USER_INPUT_METHODS:
                        return True

    return False


def contains_untrusted(node, tainted_variables):
    """
    Check whether an AST expression contains user-controlled
    data either directly or through a tainted variable.
    """

    if is_user_input(node):
        return True

    if isinstance(node, ast.Name):
        return node.id in tainted_variables

    if isinstance(node, ast.BinOp):
        return (
            contains_untrusted(node.left, tainted_variables)
            or contains_untrusted(node.right, tainted_variables)
        )

    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if contains_untrusted(
                    value.value,
                    tainted_variables
                ):
                    return True

    for child in ast.iter_child_nodes(node):
        if contains_untrusted(child, tainted_variables):
            return True

    return False


def is_ldap_search(node):
    """
    Check for ldap.search(...)
    """

    if not isinstance(node, ast.Call):
        return False

    if not isinstance(node.func, ast.Attribute):
        return False

    return (
        isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ldap"
        and node.func.attr == "search"
    )


def scan_ldap(file_path):
    """
    Detect potential LDAP injection using conservative
    user-input -> LDAP query -> ldap.search() analysis.
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
    tainted_queries = {}

    lines = code.splitlines()

    # ---------------------------------------------------------
    # Pass 1:
    # Find variables containing user-controlled input
    # and LDAP query construction.
    # ---------------------------------------------------------

    for node in ast.walk(tree):

        if not isinstance(node, ast.Assign):
            continue

        if not node.targets:
            continue

        target = node.targets[0]

        if not isinstance(target, ast.Name):
            continue

        variable_name = target.id

        # Direct user input:
        #
        # username = request.args.get("username")
        #
        # username = input(...)
        if is_user_input(node.value):
            tainted_variables.add(variable_name)
            continue

        # Query containing tainted input:
        #
        # query = "(uid=" + username + ")"
        #
        # query = f"(uid={username})"
        if contains_untrusted(
            node.value,
            tainted_variables
        ):
            tainted_queries[variable_name] = node.lineno

    # ---------------------------------------------------------
    # Pass 2:
    # Find ldap.search(query) where query is tainted.
    # ---------------------------------------------------------

    for node in ast.walk(tree):

        if not is_ldap_search(node):
            continue

        # Inspect positional arguments
        for argument in node.args:

            if (
                isinstance(argument, ast.Name)
                and argument.id in tainted_queries
            ):
                line_number = tainted_queries[argument.id]

                if 1 <= line_number <= len(lines):
                    code_line = lines[line_number - 1].strip()
                else:
                    code_line = ""

                results.append(
                    create_finding(
                        file_name=file_path,
                        line_number=line_number,
                        vulnerability_type="LDAP Injection",
                        severity="High",
                        confidence=85,
                        code=code_line,
                        owasp="A03: Injection",
                        cwe="CWE-90"
                    )
                )

                break

    return results