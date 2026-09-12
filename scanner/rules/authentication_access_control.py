import ast

from scanner.finding import create_finding


# ============================================================
# Weak Authentication Patterns
# ============================================================

WEAK_PASSWORDS = {
    "123456": 90,
    "password": 90,
    "admin": 85,
}


PASSWORD_NAMES = {
    "password",
    "passwd",
    "pwd",
    "user_password",
}


# ============================================================
# Authorization Indicators
# ============================================================

AUTHORIZATION_INDICATORS = {
    "check_admin",
    "require_admin",
    "authorize",
    "authorization",
    "is_admin",
    "current_user",
    "current_user_is_admin",
    "check_permission",
    "require_permission",
    "has_permission",
}


SENSITIVE_OPERATIONS = {
    "delete",
    "remove",
    "destroy",
}


# ============================================================
# Helper Functions
# ============================================================

def is_password_name(node):
    """
    Check whether an AST Name looks like a password variable.
    """

    return (
        isinstance(node, ast.Name)
        and node.id.lower() in PASSWORD_NAMES
    )


def get_string_value(node):
    """
    Return a string literal value from an AST node.
    """

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    return None


def contains_authorization_check(function_node):
    """
    Check whether a function contains an obvious
    authorization mechanism.
    """

    # Check function arguments.
    for argument in function_node.args.args:

        if argument.arg.lower() in AUTHORIZATION_INDICATORS:
            return True

    # Check the function body for obvious authorization calls,
    # variables, or references.
    for node in ast.walk(function_node):

        if isinstance(node, ast.Name):

            if node.id in AUTHORIZATION_INDICATORS:
                return True

        elif isinstance(node, ast.Call):

            function = node.func

            if isinstance(function, ast.Name):

                if function.id in AUTHORIZATION_INDICATORS:
                    return True

            elif isinstance(function, ast.Attribute):

                if function.attr in AUTHORIZATION_INDICATORS:
                    return True

    return False


def is_sensitive_route(function_node):
    """
    Determine whether a Flask/FastAPI route represents
    a potentially sensitive operation.

    Supported examples:

        @app.delete(...)
        @app.route(..., methods=["DELETE"])
    """

    for decorator in function_node.decorator_list:

        if not isinstance(decorator, ast.Call):
            continue

        function = decorator.func

        # -----------------------------------------------------
        # Flask/FastAPI style:
        #
        # @app.delete(...)
        # -----------------------------------------------------

        if isinstance(function, ast.Attribute):

            if function.attr.lower() in SENSITIVE_OPERATIONS:
                return True

            # -------------------------------------------------
            # Flask:
            #
            # @app.route(..., methods=["DELETE"])
            # -------------------------------------------------

            if function.attr == "route":

                for keyword in decorator.keywords:

                    if keyword.arg != "methods":
                        continue

                    value = keyword.value

                    if isinstance(value, (ast.List, ast.Tuple)):

                        for element in value.elts:

                            method = get_string_value(element)

                            if (
                                method is not None
                                and method.upper()
                                in {"DELETE", "PUT", "PATCH"}
                            ):
                                return True

    return False


# ============================================================
# Insecure Authentication
# ============================================================

def scan_insecure_authentication(tree, code, file_path):
    """
    Detect obvious weak password comparisons.

    Examples detected:

        if password == "123456":
        if password == "password":
        if password == "admin":

    Variable-based password comparisons are ignored.
    """

    results = []

    for node in ast.walk(tree):

        if not isinstance(node, ast.Compare):
            continue

        # Only handle simple comparisons:
        #
        # password == "123456"
        #
        # password != "admin"
        #
        if len(node.ops) != 1:
            continue

        if not isinstance(node.ops[0], (ast.Eq, ast.Is)):
            continue

        if len(node.comparators) != 1:
            continue

        left = node.left
        right = node.comparators[0]

        password_node = None
        literal_node = None

        if is_password_name(left):
            password_node = left
            literal_node = right

        elif is_password_name(right):
            password_node = right
            literal_node = left

        if password_node is None:
            continue

        weak_password = get_string_value(literal_node)

        if weak_password not in WEAK_PASSWORDS:
            continue

        confidence = WEAK_PASSWORDS[weak_password]

        code_line = code.splitlines()[node.lineno - 1].strip()

        results.append(
            create_finding(
                file_name=file_path,
                line_number=node.lineno,
                vulnerability_type="Insecure Authentication",
                severity="High",
                confidence=confidence,
                code=code_line,
                owasp="A07: Identification and Authentication Failures",
                cwe="CWE-521"
            )
        )

    return results


# ============================================================
# Potential Broken Access Control
# ============================================================

def scan_broken_access_control(tree, code, file_path):
    """
    Detect sensitive Flask/FastAPI routes that do not contain
    an obvious authorization mechanism.

    This is intentionally conservative.

    Confidence:
        65

    This rule does not attempt complete RBAC or authentication
    analysis.
    """

    results = []

    for node in ast.walk(tree):

        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Only inspect sensitive routes.
        if not is_sensitive_route(node):
            continue

        # Skip routes with obvious authorization mechanisms.
        if contains_authorization_check(node):
            continue

        code_line = code.splitlines()[node.lineno - 1].strip()

        results.append(
            create_finding(
                file_name=file_path,
                line_number=node.lineno,
                vulnerability_type="Potential Broken Access Control",
                severity="High",
                confidence=65,
                code=code_line,
                owasp="A01: Broken Access Control",
                cwe="CWE-862"
            )
        )

    return results


# ============================================================
# Main Scanner
# ============================================================

def scan_authentication_access_control(file_path):
    """
    Run authentication and access-control checks.

    Detects:

        1. Obvious weak password comparisons.
        2. Potential missing authorization on sensitive routes.
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

    results.extend(
        scan_insecure_authentication(
            tree,
            code,
            file_path
        )
    )

    results.extend(
        scan_broken_access_control(
            tree,
            code,
            file_path
        )
    )

    return results