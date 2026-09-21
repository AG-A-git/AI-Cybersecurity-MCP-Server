import json
import os
import sys
import tempfile
import zipfile


sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)


from scanner.parser import read_file, supported_language
from scanner.utils import (
    run_all_rules,
    deduplicate_findings
)
from scanner.finding import validate_finding


# ============================================================
# Directories that should not be scanned
# ============================================================

IGNORED_DIRECTORIES = {
    "venv",
    "node_modules",
    ".git",
    "__pycache__",
}


# ============================================================
# Finding Sorting
# ============================================================

def sort_findings(findings):
    """
    Sort findings deterministically.

    Sorting order:
        file name
        line number
        vulnerability type
    """

    return sorted(
        findings,
        key=lambda finding: (
            finding["file_name"],
            finding["line_number"],
            finding["vulnerability_type"]
        )
    )


# ============================================================
# Single File Scanner
# ============================================================

def scan_file(file_path):
    """
    Scan a single supported source-code file.
    """

    if not supported_language(file_path):
        return []

    try:
        read_file(file_path)

    except (FileNotFoundError, OSError, UnicodeError):
        return []

    findings = run_all_rules(file_path)

    validated_findings = []

    for finding in findings:
        try:
            validate_finding(finding)
            validated_findings.append(finding)

        except ValueError:
            continue

    validated_findings = deduplicate_findings(
        validated_findings
    )

    return sort_findings(validated_findings)


# ============================================================
# Directory Scanner
# ============================================================

def scan_directory(directory_path):
    """
    Scan all supported source files in a directory.
    """

    all_results = []

    for root, dirs, files in os.walk(directory_path):

        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORED_DIRECTORIES
        ]

        for file in files:

            file_path = os.path.join(
                root,
                file
            )

            if supported_language(file_path):

                results = scan_file(file_path)

                all_results.extend(results)

    all_results = deduplicate_findings(
        all_results
    )

    return sort_findings(all_results)


# ============================================================
# ZIP Scanner
# ============================================================

def scan_zip(zip_path):
    """
    Extract a ZIP project to a temporary directory,
    scan all supported source files, and return findings.

    Temporary extraction paths are removed from
    file_name before returning the findings.
    """

    if not zipfile.is_zipfile(zip_path):
        return []

    with tempfile.TemporaryDirectory() as temp_directory:

        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                archive.extractall(temp_directory)

        except (
            zipfile.BadZipFile,
            OSError,
            RuntimeError
        ):
            return []

        results = scan_directory(temp_directory)

        for finding in results:

            file_name = finding["file_name"]

            if file_name.startswith(temp_directory):

                finding["file_name"] = os.path.relpath(
                    file_name,
                    temp_directory
                )

        return sort_findings(results)


# ============================================================
# Main Scanner Entry Point
# ============================================================

def scan_project(path):
    """
    Main scanner entry point.

    Accepts:
        - A single source-code file
        - A directory containing source-code files
        - A ZIP project containing source-code files
    """

    if os.path.isfile(path):

        if path.lower().endswith(".zip"):
            return scan_zip(path)

        return scan_file(path)

    if os.path.isdir(path):
        return scan_directory(path)

    return []


# ============================================================
# JSON Report
# ============================================================

def generate_json_report(path):
    """
    Generate scanner results in JSON format.
    """

    results = scan_project(path)

    return json.dumps(
        results,
        indent=2
    )


# ============================================================
# Command-Line Entry Point
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            "Usage: python scanner\\scan.py "
            "<file_or_directory_or_zip>"
        )

        sys.exit(1)

    target = sys.argv[1]

    print(
        generate_json_report(target)
    )