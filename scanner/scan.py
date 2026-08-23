import os
import json
import sys

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from scanner.parser import read_file, supported_language
from scanner.utils import run_all_rules


# Directories that should not be scanned
IGNORED_DIRECTORIES = {
    "venv",
    "node_modules",
    ".git",
    "__pycache__",
}


def remove_duplicates(findings):
    """
    Remove duplicate vulnerability findings.

    Supports the standardized finding format while
    remaining compatible with the old format.
    """

    unique_findings = []
    seen = set()

    for finding in findings:

        key = (
            finding.get(
                "file_name",
                finding.get("file")
            ),
            finding.get(
                "line_number",
                finding.get("line")
            ),
            finding.get(
                "vulnerability_type",
                finding.get("vulnerability")
            ),
            finding.get("code"),
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings


def scan_file(file_path):
    """
    Scan a single source-code file.
    """

    if not supported_language(file_path):
        return []

    try:
        read_file(file_path)
    except Exception:
        return []

    findings = run_all_rules(file_path)

    return remove_duplicates(findings)


def scan_directory(directory_path):
    """
    Scan all supported source files in a directory.
    """

    all_results = []

    for root, dirs, files in os.walk(directory_path):

        # Do not scan virtual environments,
        # Git folders, or Python cache directories.
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORED_DIRECTORIES
        ]

        for file in files:

            file_path = os.path.join(root, file)

            if supported_language(file_path):

                results = scan_file(file_path)

                all_results.extend(results)

    return remove_duplicates(all_results)


def scan_project(path):
    """
    Main scanner entry point.

    Accepts either:
    - A single source-code file
    - A directory containing source-code files
    """

    if os.path.isfile(path):
        return scan_file(path)

    if os.path.isdir(path):
        return scan_directory(path)

    return []


def generate_json_report(path):
    """
    Generate scanner results in JSON format.
    """

    results = scan_project(path)

    return json.dumps(results, indent=2)


# Command-line entry point
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(
            "Usage: python scanner\\scan.py "
            "<file_or_directory>"
        )
        sys.exit(1)

    target = sys.argv[1]

    print(generate_json_report(target))