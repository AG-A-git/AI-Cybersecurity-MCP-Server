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

    if language == "python":
        try:
            tree = ast.parse(source)

            for node in ast.walk(tree):

                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    import_text = ast.get_source_segment(
                        source,
                        node
                    )

                    if import_text:
                        imports.append(import_text)

                elif isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    functions.append(node.name)

                elif isinstance(node, ast.Assign):

                    value = ast.get_source_segment(
                        source,
                        node.value
                    ) or ""

                    for target in node.targets:

                        if isinstance(target, ast.Name):
                            variables[target.id] = value

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