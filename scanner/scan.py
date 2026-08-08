import os
import json

from scanner.parser import read_file, supported_language
from scanner.utils import run_all_rules


def remove_duplicates(findings):
    """
    Remove duplicate vulnerability findings.
    """

    unique_findings = []
    seen = set()

    for finding in findings:

        key = (
            finding.get("file"),
            finding.get("line"),
            finding.get("vulnerability"),
            finding.get("code")
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings


def scan_file(file_path):
    """
    Scan a single source code file.
    """

    # Check whether the file type is supported
    if not supported_language(file_path):
        return []

    # Read the source code
    try:
        read_file(file_path)
    except Exception:
        return []

    # Run all vulnerability detection rules
    findings = run_all_rules(file_path)

    # Remove duplicate findings
    findings = remove_duplicates(findings)

    return findings


def scan_directory(directory_path):
    """
    Scan all supported source files in a directory.
    """

    all_results = []

    for root, dirs, files in os.walk(directory_path):

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

    # Single file
    if os.path.isfile(path):
        return scan_file(path)

    # Directory
    if os.path.isdir(path):
        return scan_directory(path)

    # Invalid path
    return []
def generate_json_report(path):
    """
    Generate scanner results in JSON format.
    """

    results = scan_project(path)

    return json.dumps(results, indent=2)