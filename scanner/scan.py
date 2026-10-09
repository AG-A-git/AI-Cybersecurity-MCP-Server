
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

    Invalid paths, unsupported files, oversized files,
    and unreadable files return an empty list.
    """

    if not isinstance(file_path, (str, os.PathLike)):
        return []

    if not supported_language(file_path):
        return []

    try:
        read_file(file_path)

    except (
        FileNotFoundError,
        OSError,
        UnicodeError,
        ValueError
    ):
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

    if not isinstance(directory_path, (str, os.PathLike)):
        return []

    try:
        if not os.path.isdir(directory_path):
            return []
    except (OSError, ValueError, TypeError):
        return []

    all_results = []

    for root, dirs, files in os.walk(directory_path):

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

    all_results = deduplicate_findings(all_results)

    return sort_findings(all_results)


# ============================================================
# ZIP Scanner
# ============================================================

def scan_zip(zip_path):
    """
    Extract a ZIP project to a temporary directory,
    scan supported source files, and return findings.

    Temporary extraction paths are removed from file_name.
    """

    if not isinstance(zip_path, (str, os.PathLike)):
        return []

    try:
        if not zipfile.is_zipfile(zip_path):
            return []
    except (OSError, ValueError, TypeError):
        return []

    with tempfile.TemporaryDirectory() as temp_directory:

        try:
            with zipfile.ZipFile(zip_path, "r") as archive:

                # Limit archive extraction.
                members = archive.infolist()
                max_files = 1000
                max_uncompressed_size = 100 * 1024 * 1024

                if len(members) > max_files:
                    return []

                total_size = sum(
                    member.file_size
                    for member in members
                )

                if total_size > max_uncompressed_size:
                    return []

                # Reject archive members that escape the
                # temporary extraction directory.
                temp_root = os.path.realpath(temp_directory)

                for member in members:
                    member_path = os.path.realpath(
                        os.path.join(
                            temp_root,
                            member.filename
                        )
                    )

                    try:
                        if (
                            os.path.commonpath(
                                [temp_root, member_path]
                            )
                            != temp_root
                        ):
                            return []
                    except ValueError:
                        return []

                archive.extractall(temp_directory)

        except (
            zipfile.BadZipFile,
            OSError,
            RuntimeError,
            ValueError,
            NotImplementedError
        ):
            return []

        results = scan_directory(temp_directory)

        # Convert temporary absolute paths to relative paths.
        for finding in results:
            file_name = finding["file_name"]

            if os.path.isabs(file_name):
                try:
                    if (
                        os.path.commonpath(
                            [
                                os.path.realpath(temp_directory),
                                os.path.realpath(file_name)
                            ]
                        )
                        == os.path.realpath(temp_directory)
                    ):
                        finding["file_name"] = os.path.relpath(
                            file_name,
                            temp_directory
                        )
                except ValueError:
                    continue

        return sort_findings(results)


# ============================================================
# Main Scanner Entry Point
# ============================================================

def scan_project(path):
    """
    Main scanner entry point.

    Accepts:
        - A single supported source-code file
        - A directory containing source-code files
        - A ZIP project containing source-code files
    """

    if not isinstance(path, (str, os.PathLike)):
        return []

    try:
        if os.path.isfile(path):

            if os.fspath(path).lower().endswith(".zip"):
                return scan_zip(path)

            return scan_file(path)

        if os.path.isdir(path):
            return scan_directory(path)

    except (OSError, ValueError, TypeError):
        return []

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

    print(generate_json_report(target))
