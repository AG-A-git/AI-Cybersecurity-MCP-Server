import os

from scanner.parser import read_file, supported_language
from utils import run_all_rules


def scan_file(file_path):
    """
    Scan a single source code file.

    Args:
        file_path: Path to the source code file.

    Returns:
        List of vulnerability findings.
    """

    # Check whether the file type is supported
    if not supported_language(file_path):
        return []

    # Read the source code
    code = read_file(file_path)

    # Run all vulnerability detection rules
    findings = run_all_rules(file_path, code)

    return findings


def scan_directory(directory_path):
    """
    Scan all supported source files in a directory.

    Args:
        directory_path: Path to the directory.

    Returns:
        List of vulnerability findings from all files.
    """

    all_results = []

    for root, dirs, files in os.walk(directory_path):

        for file in files:

            file_path = os.path.join(root, file)

            # Only scan supported file types
            if supported_language(file_path):

                results = scan_file(file_path)

                all_results.extend(results)

    return all_results


def scan_project(path):
    """
    Main scanner entry point.

    Accepts either:
    - A single source-code file
    - A directory containing source-code files

    Args:
        path: File or directory path.

    Returns:
        List of vulnerability findings.
    """

    # If the path is a single file
    if os.path.isfile(path):
        return scan_file(path)

    # If the path is a directory
    if os.path.isdir(path):
        return scan_directory(path)

    # Invalid path
    return []