import ast

from scanner.finding import create_finding


SENSITIVE_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "private_key",
    "client_secret",
    "credit_card",
}


EXPOSURE_FUNCTIONS = {
    "print",
    "log",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    "exception",
}


def is_sensitive_name(node):
    """
    Check whether an AST name represents sensitive data.
    """
    return (
        isinstance(node, ast.Name)
        and node.id.lower() in SENSITIVE_NAMES
    )


def contains_sensitive_data(node):
    """
    Recursively check whether an expression contains
    a sensitive variable.
    """
    if is_sensitive_name(node):
        return True

    for child in ast.iter_child_nodes(node):
        if contains_sensitive_data(child):
            return True

    return False


def is_exposure_call(node):
    """
    Check whether a function call exposes data through
    print() or common logging functions.
    """
    if not isinstance(node, ast.Call):
        return False

    function = node.func

    # print(secret)
    if isinstance(function, ast.Name):
        return function.id in EXPOSURE_FUNCTIONS

    # logger.info(secret)
    if isinstance(function, ast.Attribute):
        return function.attr in EXPOSURE_FUNCTIONS

    return False


def scan_sensitive_data_exposure(file_path):
    """
    Detect sensitive variables exposed through printing
    or logging.

    Examples:
        print(password)
        logger.info(secret)
        logging.error(api_key)

    Does not flag unrelated variables such as:
        token_count = 10
        print(token_count)
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

    lines = code.splitlines()

    for node in ast.walk(tree):

        if not is_exposure_call(node):
            continue

        if not any(
            contains_sensitive_data(argument)
            for argument in node.args
        ):
            continue

        code_line = lines[node.lineno - 1].strip()

        results.append(
            create_finding(
                file_name=file_path,
                line_number=node.lineno,
                vulnerability_type="Sensitive Data Exposure",
                severity="High",
                confidence=90,
                code=code_line,
                owasp="A02: Cryptographic Failures",
                cwe="CWE-532"
            )
        )

    return results