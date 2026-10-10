from pathlib import Path

from scanner.utils import run_all_rules, remove_duplicates
from scanner.scan import scan_zip


# Source-code extensions supported by the scanner
SUPPORTED_EXTENSIONS = {".py", ".js"}


# Directories that should not be scanned
IGNORED_DIRECTORIES = {
    "venv",
    "node_modules",
    ".git",
    "__pycache__",
}


def find_source_files(path):
    """
    Find supported source files in a file or project directory.

    Supported extensions:
        .py
        .js

    Ignored directories inside the selected project:
        venv/
        node_modules/
        .git/
        __pycache__/
    """
    path = Path(path)

    # If the input is a single file
    if path.is_file():
        if path.suffix.lower() in SUPPORTED_EXTENSIONS:
            return [path]

        return []

    # If the input is a directory
    if path.is_dir():
        source_files = []

        for file in path.rglob("*"):
            # Skip entries that are not files
            if not file.is_file():
                continue

            # Check only directories relative to the selected project root.
            # Ancestors outside the project must not cause files to be skipped.
            relative_path = file.relative_to(path)

            if any(
                directory in IGNORED_DIRECTORIES
                for directory in relative_path.parts[:-1]
            ):
                continue

            # Only include supported source-code files
            if file.suffix.lower() in SUPPORTED_EXTENSIONS:
                source_files.append(file)

        return source_files

    raise FileNotFoundError(f"Path does not exist: {path}")


def scan_project(project_path):
    """
    Scan a source file, project directory, or ZIP project.

    Args:
        project_path: Path to a source file, project directory,
                      or ZIP project.

    Returns:
        list: Security findings.
    """
    # Support ZIP projects for the MCP backend
    if str(project_path).lower().endswith(".zip"):
        return scan_zip(project_path)

    source_files = find_source_files(project_path)

    results = []

    for file_path in source_files:
        file_results = run_all_rules(str(file_path))
        results.extend(file_results)

    return remove_duplicates(results)