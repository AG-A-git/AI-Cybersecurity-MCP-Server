import json
import os
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

    # --------------------------------------------------------
    # Run every registered vulnerability rule.
    # --------------------------------------------------------

    findings = run_all_rules(file_path)

    # --------------------------------------------------------
    # Validate every finding centrally.
    # --------------------------------------------------------

    validated_findings = []

    for finding in findings:

        try:
            validate_finding(finding)
            validated_findings.append(finding)

        except ValueError:
            continue

    # --------------------------------------------------------
    # Remove duplicate findings.
    # --------------------------------------------------------

    validated_findings = deduplicate_findings(
        validated_findings
    )

    # --------------------------------------------------------
    # Sort for deterministic API output.
    # --------------------------------------------------------

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

        # Do not scan virtual environments,
        # Git folders, or Python cache directories.
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

    # --------------------------------------------------------
    # Deduplicate results across files.
    # --------------------------------------------------------

    all_results = deduplicate_findings(
        all_results
    )

    # --------------------------------------------------------
    # Sort final results.
    # --------------------------------------------------------

    return sort_findings(all_results)


# ============================================================
# Main Scanner Entry Point
# ============================================================

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
            "<file_or_directory>"
        )

        sys.exit(1)

    target = sys.argv[1]

    print(
        generate_json_report(target)
    )