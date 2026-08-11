from pathlib import Path

from scanner.utils import run_all_rules, remove_duplicates


SUPPORTED_EXTENSIONS = {".py", ".js"}


def find_source_files(path):
    """
    Find supported source files in a file or project directory.
    """

    path = Path(path)

    if path.is_file():
        if path.suffix.lower() in SUPPORTED_EXTENSIONS:
            return [path]
        return []

    if path.is_dir():
        return [
            file
            for file in path.rglob("*")
            if file.is_file()
            and file.suffix.lower() in SUPPORTED_EXTENSIONS
        ]

    raise FileNotFoundError(f"Path does not exist: {path}")


def scan_project(project_path):
    """
    Scan a file or project directory.

    Returns:
        list: JSON-compatible vulnerability findings.
    """

    source_files = find_source_files(project_path)

    results = []

    for file_path in source_files:
        file_results = run_all_rules(str(file_path))
        results.extend(file_results)

    return remove_duplicates(results)