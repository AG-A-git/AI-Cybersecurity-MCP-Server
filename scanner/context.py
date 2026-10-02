import ast
import os

from scanner.parser import read_file


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
    variables = {}
    references = {}
    variable_lines = {}

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
                        node
                    )

                    if import_text:
                        imports.append(import_text)

                # --------------------------------------------------
                # Functions
                # --------------------------------------------------
                elif isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    functions.append(node.name)

                # --------------------------------------------------
                # Variable assignments
                # --------------------------------------------------
                elif isinstance(node, ast.Assign):

                    value = ast.get_source_segment(
                        source,
                        node.value
                    ) or ""

                    # Find variables referenced by the assigned value.
                    #
                    # Example:
                    #   username = request.args.get("username")
                    #   query = "SELECT ..." + username
                    #
                    # This produces:
                    #   references["username"] == ["request"]
                    #   references["query"] == ["username"]
                    referenced_names = [
                        child.id
                        for child in ast.walk(node.value)
                        if isinstance(child, ast.Name)
                    ]

                    for target in node.targets:

                        if isinstance(target, ast.Name):
                            variables[target.id] = value
                            references[target.id] = referenced_names
                            variable_lines[target.id] = node.lineno

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
        "variables": variables,
        "references": references,
        "variable_lines": variable_lines,
    }


def get_source_context(context, line_number, before=2, after=2):
    """
    Return source-code context surrounding a finding.

    Args:
        context: Shared rule context.
        line_number: 1-based source line number.
        before: Number of lines before the finding.
        after: Number of lines after the finding.

    Returns:
        dict containing the requested source lines.
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


def is_variable_derived_from(context, variable_name, source_variables, visited=None):
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
