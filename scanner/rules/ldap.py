import ast

from scanner.context import build_rule_context, get_source_context
from scanner.finding import create_finding


USER_INPUT_METHODS = {
    "args.get",
    "form.get",
    "values.get",
    "json.get",
}


def is_user_input(node):
    """Check whether an AST node represents supported user input."""

    if not isinstance(node, ast.Call):
        return False

    # input(...)
    if isinstance(node.func, ast.Name):
        return node.func.id == "input"

    # request.args.get(...), request.form.get(...), etc.
    if not isinstance(node.func, ast.Attribute):
        return False

    if node.func.attr != "get":
        return False

    request_obj = node.func.value

    if not isinstance(request_obj, ast.Attribute):
        return False

    if not isinstance(request_obj.value, ast.Name):
        return False

    if request_obj.value.id != "request":
        return False

    return f"{request_obj.attr}.get" in USER_INPUT_METHODS


def contains_untrusted(node, tainted_variables):
    """Check whether an expression contains user-controlled data."""

    if is_user_input(node):
        return True

    if isinstance(node, ast.Name):
        return node.id in tainted_variables

    # Handles f-strings, concatenation, percent formatting,
    # .format(), and expressions containing nested variables.
    return any(
        contains_untrusted(child, tainted_variables)
        for child in ast.iter_child_nodes(node)
    )


def is_ldap_search(node):
    """Check for calls such as ldap.search(query)."""

    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ldap"
        and node.func.attr == "search"
    )


def get_assignment_target_names(node):
    """Return simple variable names assigned by an assignment."""

    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        targets = [node.target]
    else:
        return []

    names = []

    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            names.extend(
                element.id
                for element in target.elts
                if isinstance(element, ast.Name)
            )

    return names


def scan_ldap(file_path):
    """
    Detect potential LDAP injection when user-controlled input
    reaches a query passed to ldap.search().
    """

    results = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            code = file.read()
    except (FileNotFoundError, OSError):
        return results

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return results

    try:
        context = build_rule_context(file_path)
    except (SyntaxError, ValueError, OSError, UnicodeError):
        context = {"lines": code.splitlines()}

    lines = code.splitlines()
    tainted_variables = set()
    tainted_queries = {}

    # Process assignments in source order, then repeat until
    # taint propagation stabilizes. This handles intermediate
    # variables even when the source appears several assignments
    # before the final LDAP query.
    assignments = sorted(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )

    changed = True

    while changed:
        changed = False

        for node in assignments:
            if isinstance(node, ast.Assign):
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                value = node.value
            else:
                value = node.value

            if value is None:
                continue

            targets = get_assignment_target_names(node)

            if not targets:
                continue

            if not contains_untrusted(value, tainted_variables):
                continue

            for variable_name in targets:
                if variable_name not in tainted_variables:
                    tainted_variables.add(variable_name)
                    changed = True

                # Keep the first source-ordered assignment that
                # constructs a tainted value for this variable.
                tainted_queries.setdefault(variable_name, node.lineno)

    # Find LDAP searches receiving tainted arguments.
    seen = set()

    for node in ast.walk(tree):
        if not is_ldap_search(node):
            continue

        arguments = list(node.args)
        arguments.extend(keyword.value for keyword in node.keywords)

        tainted_argument = next(
            (
                argument
                for argument in arguments
                if contains_untrusted(argument, tainted_variables)
            ),
            None,
        )

        if tainted_argument is None:
            continue

        # Prefer the query-construction line for a named query.
        if isinstance(tainted_argument, ast.Name):
            line_number = tainted_queries.get(
                tainted_argument.id,
                node.lineno,
            )
        else:
            line_number = node.lineno

        line_number = max(1, min(line_number, len(lines))) if lines else 1
        code_line = lines[line_number - 1].strip() if lines else ""

        fingerprint_key = (
            file_path,
            line_number,
            "LDAP Injection",
        )

        if fingerprint_key in seen:
            continue

        seen.add(fingerprint_key)

        finding = create_finding(
            file_name=file_path,
            line_number=line_number,
            vulnerability_type="LDAP Injection",
            severity="High",
            confidence=85,
            code=code_line,
            owasp="A03: Injection",
            cwe="CWE-90",
        )

        finding["source_context"] = get_source_context(
            context,
            line_number,
        )

        results.append(finding)

    return results
