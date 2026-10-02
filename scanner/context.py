import ast
import os

from scanner.parser import read_file


def _extract_referenced_names(node):
    """
    Extract variable names referenced by an AST node.

    Returns:
        list[str]: Referenced variable names.
    """

    if node is None:
        return []

    return [
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name)
        and isinstance(child.ctx, ast.Load)
    ]


def _get_value_text(source, node):
    """
    Safely get the source-code text represented by an AST node.
    """

    if node is None:
        return ""

    return ast.get_source_segment(source, node) or ""


def _get_target_names(target):
    """
    Return simple variable names from an assignment target.

    Supports:
        x = value
        x, y = value
    """

    if isinstance(target, ast.Name):
        return [target.id]

    if isinstance(target, (ast.Tuple, ast.List)):
        names = []

        for element in target.elts:
            if isinstance(element, ast.Name):
                names.append(element.id)

        return names

    return []


def classify_source(node):
    """
    Classify the direct source represented by an AST expression.

    Returns:
        dict containing:
            source_type
            source_expression
    """

    if node is None:
        return {
            "source_type": "unknown",
            "source_expression": "",
        }

    try:
        source_expression = ast.unparse(node)
    except Exception:
        source_expression = ""

    # --------------------------------------------------------------
    # Constants
    # --------------------------------------------------------------
    if isinstance(
        node,
        (
            ast.Constant,
            ast.List,
            ast.Tuple,
            ast.Set,
            ast.Dict,
        ),
    ):
        return {
            "source_type": "constant",
            "source_expression": source_expression,
        }

    # --------------------------------------------------------------
    # Direct HTTP request attributes
    #
    # Examples:
    #   request.json
    #   request.data
    #   request.args
    #   request.form
    # --------------------------------------------------------------
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            if node.value.id in {"request", "req"} and node.attr in {
                "args",
                "form",
                "json",
                "data",
                "values",
                "query",
            }:
                return {
                    "source_type": "http_request",
                    "source_expression": source_expression,
                }

    # --------------------------------------------------------------
    # Function calls
    # --------------------------------------------------------------
    if isinstance(node, ast.Call):
        function = node.func

        if isinstance(function, ast.Attribute):

            # ------------------------------------------------------
            # request.args.get(...)
            # request.form.get(...)
            # request.values.get(...)
            # request.query.get(...)
            # ------------------------------------------------------
            if isinstance(function.value, ast.Attribute):
                base = function.value

                if (
                    isinstance(base.value, ast.Name)
                    and base.value.id in {"request", "req"}
                    and base.attr in {
                        "args",
                        "form",
                        "values",
                        "query",
                    }
                    and function.attr in {
                        "get",
                        "getlist",
                        "pop",
                    }
                ):
                    return {
                        "source_type": "http_request",
                        "source_expression": source_expression,
                    }

            # ------------------------------------------------------
            # request.get_json()
            # request.get_data()
            # ------------------------------------------------------
            if (
                isinstance(function.value, ast.Name)
                and function.value.id in {"request", "req"}
                and function.attr in {
                    "get_json",
                    "get_data",
                }
            ):
                return {
                    "source_type": "http_request",
                    "source_expression": source_expression,
                }

            # ------------------------------------------------------
            # os.environ.get(...)
            # os.environ.pop(...)
            # ------------------------------------------------------
            if (
                isinstance(function.value, ast.Attribute)
                and isinstance(function.value.value, ast.Name)
                and function.value.value.id == "os"
                and function.value.attr == "environ"
                and function.attr in {
                    "get",
                    "pop",
                }
            ):
                return {
                    "source_type": "environment",
                    "source_expression": source_expression,
                }

    # --------------------------------------------------------------
    # os.environ["NAME"]
    # --------------------------------------------------------------
    if isinstance(node, ast.Subscript):
        value = node.value

        if (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "os"
            and value.attr == "environ"
        ):
            return {
                "source_type": "environment",
                "source_expression": source_expression,
            }

    return {
        "source_type": "unknown",
        "source_expression": source_expression,
    }


def classify_sink(node):
    """
    Classify a dangerous operation represented by an AST call.

    This only identifies the sink category.
    It does not determine whether the value reaching the sink
    is actually vulnerable.

    Returns:
        dict containing:
            sink_type
            sink_expression
    """

    if node is None:
        return {
            "sink_type": "unknown",
            "sink_expression": "",
        }

    try:
        sink_expression = ast.unparse(node)
    except Exception:
        sink_expression = ""

    if not isinstance(node, ast.Call):
        return {
            "sink_type": "unknown",
            "sink_expression": sink_expression,
        }

    function = node.func

    # --------------------------------------------------------------
    # SQL sinks
    #
    # Examples:
    #   cursor.execute(query)
    #   db.execute(query)
    #   connection.execute(query)
    #   cursor.executemany(query, values)
    #   cursor.executescript(query)
    # --------------------------------------------------------------
    if isinstance(function, ast.Attribute):
        if function.attr in {
            "execute",
            "executemany",
            "executescript",
        }:
            return {
                "sink_type": "sql",
                "sink_expression": sink_expression,
            }

    # --------------------------------------------------------------
    # Command execution sinks
    #
    # Examples:
    #   os.system(command)
    #   os.popen(command)
    #   subprocess.run(command, shell=True)
    #   subprocess.call(command, shell=True)
    #   subprocess.Popen(command, shell=True)
    # --------------------------------------------------------------
    if isinstance(function, ast.Attribute):

        if (
            isinstance(function.value, ast.Name)
            and function.value.id == "os"
            and function.attr in {
                "system",
                "popen",
            }
        ):
            return {
                "sink_type": "command",
                "sink_expression": sink_expression,
            }

        if (
            isinstance(function.value, ast.Name)
            and function.value.id == "subprocess"
            and function.attr in {
                "run",
                "call",
                "Popen",
                "check_call",
                "check_output",
            }
        ):
            return {
                "sink_type": "command",
                "sink_expression": sink_expression,
            }

    # --------------------------------------------------------------
    # Network / SSRF sinks
    #
    # Examples:
    #   requests.get(url)
    #   requests.post(url)
    #   requests.request("GET", url)
    #   httpx.get(url)
    #   urllib.request.urlopen(url)
    # --------------------------------------------------------------
    if isinstance(function, ast.Attribute):

        if (
            isinstance(function.value, ast.Name)
            and function.value.id in {
                "requests",
                "httpx",
            }
            and function.attr in {
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "request",
                "head",
                "options",
            }
        ):
            return {
                "sink_type": "network",
                "sink_expression": sink_expression,
            }

        if function.attr in {
            "urlopen",
            "urlretrieve",
        }:
            return {
                "sink_type": "network",
                "sink_expression": sink_expression,
            }

    # --------------------------------------------------------------
    # HTML / XSS sinks
    #
    # Examples:
    #   render_template_string(html)
    #   Markup(html)
    #   make_response(html)
    # --------------------------------------------------------------
    if isinstance(function, ast.Name):
        if function.id in {
            "render_template_string",
            "Markup",
            "make_response",
        }:
            return {
                "sink_type": "html",
                "sink_expression": sink_expression,
            }

    # --------------------------------------------------------------
    # LDAP sinks
    #
    # Examples:
    #   ldap.search_s(...)
    #   ldap.search_ext_s(...)
    #   ldap.search(...)
    # --------------------------------------------------------------
    if isinstance(function, ast.Attribute):
        if function.attr in {
            "search_s",
            "search_ext_s",
            "search",
        }:
            return {
                "sink_type": "ldap",
                "sink_expression": sink_expression,
            }

    return {
        "sink_type": "unknown",
        "sink_expression": sink_expression,
    }


def _record_assignment(
    source,
    node,
    value_node,
    variables,
    references,
    variable_lines,
    assignment_history,
    variable_sources,
):
    """
    Record one variable assignment and its references.
    """

    value = _get_value_text(source, value_node)
    referenced_names = _extract_referenced_names(value_node)

    target_names = []

    if isinstance(node, ast.Assign):
        for target in node.targets:
            target_names.extend(_get_target_names(target))

    elif isinstance(node, ast.AnnAssign):
        target_names.extend(_get_target_names(node.target))

    elif isinstance(node, ast.AugAssign):
        target_names.extend(_get_target_names(node.target))

        # Augmented assignment reads the previous value too.
        if isinstance(node.target, ast.Name):
            if node.target.id not in referenced_names:
                referenced_names.insert(0, node.target.id)

    source_info = classify_source(value_node)

    for target_name in target_names:
        variables[target_name] = value
        references[target_name] = list(referenced_names)
        variable_lines[target_name] = node.lineno

        variable_sources[target_name] = {
            "source_type": source_info["source_type"],
            "source_expression": source_info["source_expression"],
            "line": node.lineno,
        }

        assignment_history.append({
            "name": target_name,
            "line": node.lineno,
            "value": value,
            "references": list(referenced_names),
            "assignment_type": type(node).__name__,
            "source_type": source_info["source_type"],
        })


def build_rule_context(file_path):
    """
    Build lightweight shared context for vulnerability rules.

    The context provides common source-code information so that
    multiple rules do not need to independently read and parse
    the same file.

    Returns:
        dict: Shared rule-analysis context.
    """

    source = read_file(file_path)

    extension = os.path.splitext(file_path)[1].lower()

    if extension == ".py":
        language = "python"
    elif extension == ".js":
        language = "javascript"
    else:
        language = "unknown"

    lines = source.splitlines()

    imports = []
    functions = []
    functions_detail = []
    classes = []
    decorators = []

    variables = {}
    references = {}
    variable_lines = {}
    assignment_history = []
    variable_sources = {}

    if language == "python":
        try:
            tree = ast.parse(source)

            for node in ast.walk(tree):

                # --------------------------------------------------
                # Imports
                # --------------------------------------------------
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    import_text = ast.get_source_segment(
                        source,
                        node,
                    )

                    if import_text:
                        imports.append(import_text)

                # --------------------------------------------------
                # Classes
                # --------------------------------------------------
                elif isinstance(node, ast.ClassDef):
                    class_decorators = [
                        ast.get_source_segment(
                            source,
                            decorator,
                        )
                        for decorator in node.decorator_list
                    ]

                    class_decorators = [
                        decorator
                        for decorator in class_decorators
                        if decorator
                    ]

                    classes.append({
                        "name": node.name,
                        "line": node.lineno,
                        "end_line": getattr(
                            node,
                            "end_lineno",
                            node.lineno,
                        ),
                        "decorators": class_decorators,
                    })

                    decorators.extend(class_decorators)

                # --------------------------------------------------
                # Functions
                # --------------------------------------------------
                elif isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef),
                ):
                    functions.append(node.name)

                    function_decorators = [
                        ast.get_source_segment(
                            source,
                            decorator,
                        )
                        for decorator in node.decorator_list
                    ]

                    function_decorators = [
                        decorator
                        for decorator in function_decorators
                        if decorator
                    ]

                    functions_detail.append({
                        "name": node.name,
                        "line": node.lineno,
                        "end_line": getattr(
                            node,
                            "end_lineno",
                            node.lineno,
                        ),
                        "decorators": function_decorators,
                    })

                    decorators.extend(function_decorators)

                # --------------------------------------------------
                # Normal assignments
                # --------------------------------------------------
                elif isinstance(node, ast.Assign):
                    _record_assignment(
                        source,
                        node,
                        node.value,
                        variables,
                        references,
                        variable_lines,
                        assignment_history,
                        variable_sources,
                    )

                # --------------------------------------------------
                # Annotated assignments
                # --------------------------------------------------
                elif isinstance(node, ast.AnnAssign):
                    _record_assignment(
                        source,
                        node,
                        node.value,
                        variables,
                        references,
                        variable_lines,
                        assignment_history,
                        variable_sources,
                    )

                # --------------------------------------------------
                # Augmented assignments
                # --------------------------------------------------
                elif isinstance(node, ast.AugAssign):
                    _record_assignment(
                        source,
                        node,
                        node.value,
                        variables,
                        references,
                        variable_lines,
                        assignment_history,
                        variable_sources,
                    )

        except SyntaxError:
            # Context creation must not crash scanning.
            pass

    return {
        "file_name": str(file_path),
        "language": language,
        "source": source,
        "lines": lines,
        "imports": imports,
        "functions": functions,
        "functions_detail": functions_detail,
        "classes": classes,
        "decorators": decorators,
        "variables": variables,
        "references": references,
        "variable_lines": variable_lines,
        "assignment_history": assignment_history,
        "variable_sources": variable_sources,
    }


def get_source_context(context, line_number, before=2, after=2):
    """
    Return source-code context surrounding a finding.
    """

    lines = context.get("lines", [])

    if not lines:
        return {
            "start_line": line_number,
            "end_line": line_number,
            "lines": [],
        }

    start = max(1, line_number - before)
    end = min(len(lines), line_number + after)

    return {
        "start_line": start,
        "end_line": end,
        "lines": lines[start - 1:end],
    }


def get_function_context(context, line_number):
    """
    Return the function and class containing a source line.

    The nearest enclosing function is returned. If the function is
    a method inside a class, the enclosing class is also returned.
    """

    functions_detail = context.get("functions_detail", [])
    classes = context.get("classes", [])

    function_name = None
    function_line = None
    function_end_line = None

    class_name = None
    class_line = None
    class_end_line = None

    matching_functions = [
        function
        for function in functions_detail
        if function["line"] <= line_number <= function["end_line"]
    ]

    if matching_functions:
        function = min(
            matching_functions,
            key=lambda item: (
                item["end_line"] - item["line"],
                item["line"],
            ),
        )

        function_name = function["name"]
        function_line = function["line"]
        function_end_line = function["end_line"]

    matching_classes = [
        class_info
        for class_info in classes
        if class_info["line"] <= line_number <= class_info["end_line"]
    ]

    if matching_classes:
        class_info = min(
            matching_classes,
            key=lambda item: (
                item["end_line"] - item["line"],
                item["line"],
            ),
        )

        class_name = class_info["name"]
        class_line = class_info["line"]
        class_end_line = class_info["end_line"]

    return {
        "function_name": function_name,
        "function_line": function_line,
        "function_end_line": function_end_line,
        "class_name": class_name,
        "class_line": class_line,
        "class_end_line": class_end_line,
    }


def is_variable_derived_from(
    context,
    variable_name,
    source_variables,
    visited=None,
):
    """
    Determine whether a variable ultimately depends on one of the
    supplied source variables.

    The lookup follows the shared context reference graph recursively.
    """

    if visited is None:
        visited = set()

    if variable_name in source_variables:
        return True

    if variable_name in visited:
        return False

    visited.add(variable_name)

    references = context.get("references", {})

    for referenced_variable in references.get(variable_name, []):
        if is_variable_derived_from(
            context,
            referenced_variable,
            source_variables,
            visited,
        ):
            return True

    return False


def build_project_context(file_paths):
    """
    Build isolated rule contexts for multiple source files.

    Each file keeps its own variable and reference namespace so
    similarly named variables in different files are not mixed.
    """

    project_context = {}

    for file_path in file_paths:
        context = build_rule_context(file_path)
        project_context[str(file_path)] = context

    return project_context


def get_vulnerability_context(
    context,
    source_line=None,
    sink_line=None,
    before=2,
    after=2,
):
    """
    Build combined context around a vulnerability source and sink.

    Returns source and sink source-code windows together with
    function/class information for both locations.
    """

    result = {
        "source": None,
        "sink": None,
    }

    if source_line is not None:
        result["source"] = {
            "line": source_line,
            "context": get_source_context(
                context,
                source_line,
                before=before,
                after=after,
            ),
            "function": get_function_context(
                context,
                source_line,
            ),
        }

    if sink_line is not None:
        result["sink"] = {
            "line": sink_line,
            "context": get_source_context(
                context,
                sink_line,
                before=before,
                after=after,
            ),
            "function": get_function_context(
                context,
                sink_line,
            ),
        }

    return result







def get_ssrf_context(node, context=None):
    """
    Extract context for a potential SSRF/network sink.

    Returns:
        dict containing:
            sink_type
            sink_expression
            url_argument
            url_argument_type
            dynamic_url
            source_type (when available)
    """

    result = {
        "sink_type": "unknown",
        "sink_expression": "",
        "url_argument": None,
        "url_argument_type": None,
        "dynamic_url": False,
    }

    if node is None:
        return result

    try:
        result["sink_expression"] = ast.unparse(node)
    except Exception:
        result["sink_expression"] = ""

    sink = classify_sink(node)

    if sink["sink_type"] != "network":
        return result

    result["sink_type"] = "network"

    if not isinstance(node, ast.Call) or not node.args:
        return result

    # requests.request("GET", url) uses the second positional argument.
    # Other network sinks normally use the first argument as the URL.
    url_node = node.args[0]

    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "requests"
        and node.func.attr == "request"
        and len(node.args) >= 2
    ):
        url_node = node.args[1]

    try:
        result["url_argument"] = ast.unparse(url_node)
    except Exception:
        result["url_argument"] = None

    if isinstance(url_node, ast.Constant):
        result["url_argument_type"] = "constant"
        result["dynamic_url"] = False

    elif isinstance(url_node, ast.Name):
        result["url_argument_type"] = "variable"
        result["dynamic_url"] = True

        if context is not None:
            variable_sources = context.get("variable_sources", {})
            source_info = variable_sources.get(url_node.id)

            if isinstance(source_info, dict):
                result["source_type"] = source_info.get("source_type")

    elif isinstance(url_node, (ast.JoinedStr, ast.BinOp)):
        result["url_argument_type"] = "dynamic_expression"
        result["dynamic_url"] = True

    else:
        result["url_argument_type"] = "expression"
        result["dynamic_url"] = True

    return result


def get_command_injection_context(node, context=None):
    """
    Extract context for a potential command injection sink.

    Returns:
        dict containing:
            sink_type
            sink_expression
            command_argument
            command_argument_type
            dynamic_command
            source_type (when available)
    """

    result = {
        "sink_type": "unknown",
        "sink_expression": "",
        "command_argument": None,
        "command_argument_type": None,
        "dynamic_command": False,
    }

    if node is None:
        return result

    try:
        result["sink_expression"] = ast.unparse(node)
    except Exception:
        result["sink_expression"] = ""

    sink = classify_sink(node)

    if sink["sink_type"] != "command":
        return result

    result["sink_type"] = "command"

    if not isinstance(node, ast.Call) or not node.args:
        return result

    command_node = node.args[0]

    try:
        result["command_argument"] = ast.unparse(command_node)
    except Exception:
        result["command_argument"] = None

    if isinstance(command_node, ast.Constant):
        result["command_argument_type"] = "constant"
        result["dynamic_command"] = False

    elif isinstance(command_node, ast.Name):
        result["command_argument_type"] = "variable"
        result["dynamic_command"] = True

        if context is not None:
            variable_sources = context.get("variable_sources", {})
            source_info = variable_sources.get(command_node.id)

            if isinstance(source_info, dict):
                result["source_type"] = source_info.get("source_type")

    elif isinstance(command_node, (ast.JoinedStr, ast.BinOp)):
        result["command_argument_type"] = "dynamic_expression"
        result["dynamic_command"] = True

    else:
        result["command_argument_type"] = "expression"
        result["dynamic_command"] = True

    return result


def get_xss_context(node, context=None):
    """
    Extract context for a potential Cross-Site Scripting sink.

    Returns:
        dict containing:
            sink_type
            sink_expression
            html_argument
            html_argument_type
            dynamic_html
            source_type (when available)
    """

    result = {
        "sink_type": "unknown",
        "sink_expression": "",
        "html_argument": None,
        "html_argument_type": None,
        "dynamic_html": False,
    }

    if node is None:
        return result

    try:
        result["sink_expression"] = ast.unparse(node)
    except Exception:
        result["sink_expression"] = ""

    sink = classify_sink(node)

    if sink["sink_type"] != "html":
        return result

    result["sink_type"] = "html"

    if not isinstance(node, ast.Call) or not node.args:
        return result

    html_node = node.args[0]

    try:
        result["html_argument"] = ast.unparse(html_node)
    except Exception:
        result["html_argument"] = None

    if isinstance(html_node, ast.Constant):
        result["html_argument_type"] = "constant"
        result["dynamic_html"] = False

    elif isinstance(html_node, ast.Name):
        result["html_argument_type"] = "variable"
        result["dynamic_html"] = True

        if context is not None:
            variable_sources = context.get("variable_sources", {})
            source_info = variable_sources.get(html_node.id)

            if isinstance(source_info, dict):
                result["source_type"] = source_info.get("source_type")

    elif isinstance(html_node, (ast.JoinedStr, ast.BinOp)):
        result["html_argument_type"] = "dynamic_expression"
        result["dynamic_html"] = True

    else:
        result["html_argument_type"] = "expression"
        result["dynamic_html"] = True

    return result

def get_sql_injection_context(node, context=None):
    """
    Extract SQL-specific context from a SQL sink AST call.

    Returns:
        dict containing sink information and query construction details.
    """

    result = {
        "sink_type": "unknown",
        "sink_expression": "",
        "query_argument": None,
        "query_argument_type": None,
        "dynamic_query": False,
    }

    if node is None:
        return result

    try:
        result["sink_expression"] = ast.unparse(node)
    except Exception:
        result["sink_expression"] = ""

    sink = classify_sink(node)

    if sink["sink_type"] != "sql":
        return result

    result["sink_type"] = "sql"

    if not isinstance(node, ast.Call) or not node.args:
        return result

    query_node = node.args[0]

    try:
        result["query_argument"] = ast.unparse(query_node)
    except Exception:
        result["query_argument"] = None

    if isinstance(query_node, ast.Constant):
        result["query_argument_type"] = "constant"
        result["dynamic_query"] = False

    elif isinstance(query_node, ast.Name):
        result["query_argument_type"] = "variable"
        result["dynamic_query"] = True

        if context is not None:
            variable_sources = context.get("variable_sources", {})
            source_info = variable_sources.get(query_node.id)

            if isinstance(source_info, dict):
                result["source_type"] = source_info.get("source_type")

    elif isinstance(query_node, (ast.JoinedStr, ast.BinOp)):
        result["query_argument_type"] = "dynamic_expression"
        result["dynamic_query"] = True

    else:
        result["query_argument_type"] = "expression"
        result["dynamic_query"] = True

    return result
def get_auth_context(node):
    """
    Extract authentication/authorization evidence from an AST node.

    Returns:
        dict containing:
            auth_type
            auth_expression
            evidence
    """

    result = {
        "auth_type": "unknown",
        "auth_expression": "",
        "evidence": None,
    }

    if node is None:
        return result

    try:
        result["auth_expression"] = ast.unparse(node)
    except Exception:
        result["auth_expression"] = ""

    # Authentication/authorization decorators.
    if isinstance(node, ast.Name):
        name = node.id.lower()

        if name in {
            "login_required",
            "authenticated",
            "authentication_required",
            "requires_auth",
            "require_auth",
            "authorize",
            "authorized",
        }:
            result["auth_type"] = "authentication"
            result["evidence"] = name
            return result

    # Authentication/authorization calls.
    if isinstance(node, ast.Call):
        function_name = ""

        if isinstance(node.func, ast.Name):
            function_name = node.func.id.lower()

        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr.lower()

        if function_name in {
            "authenticate",
            "login_required",
            "authorize",
            "check_permission",
            "has_permission",
            "require_permission",
        }:
            result["auth_type"] = "authentication"
            result["evidence"] = function_name
            return result

    # Common authentication state checks.
    if isinstance(node, ast.Attribute):
        attribute_name = node.attr.lower()

        if attribute_name in {
            "is_authenticated",
            "is_admin",
            "is_staff",
            "is_superuser",
            "permissions",
            "roles",
        }:
            result["auth_type"] = "authorization"
            result["evidence"] = attribute_name
            return result

    return result
