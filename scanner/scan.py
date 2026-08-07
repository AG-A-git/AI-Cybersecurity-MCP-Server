import os

from scanner.parser import (
    read_file,
    supported_language
)

from utils import run_all_rules


def scan_file(file_path):
    """
    Scan a single source code file.
    """

    if not supported_language(file_path):
        return []

    code = read_file(file_path)

    results = run_all_rules(file_path, code)

    return results

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

    return all_results
def scan_project(path):
    """
    Main scanner entry point.
    Accepts either a file or directory.
    """

    if os.path.isfile(path):
        return scan_file(path)

    if os.path.isdir(path):
        return scan_directory(path)

    return []





import json
import sys

from parser import parse_file
from rules.sql import detect_sql_injection
from rules.credentials import detect_hardcoded_credentials


def scan_file(file_path):
    """
    Scan a source code file for vulnerabilities.
    """

    parsed = parse_file(file_path)

    code = parsed["code"]

    findings = []

    # Run all rules
    findings.extend(detect_sql_injection(code))
    findings.extend(detect_hardcoded_credentials(code))

    result = {
        "file": parsed["file"],
        "language": parsed["language"],
        "total_findings": len(findings),
        "findings": findings
    }

    return result


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:")
        print("python scanner/scan.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        result = scan_file(file_path)

        print(json.dumps(result, indent=4))

    except Exception as e:
        print(f"Error: {e}")


        """
Scanner Workflow

1. Accept project or file path from backend.

2. Read all supported source files.

3. Detect programming language.

4. Load vulnerability detection rules.

5. Execute rules on every file.

6. Collect all detected vulnerabilities.

7. Assign severity to each finding.

8. Generate JSON report.

9. Return report to backend API.
"""

# Actual implementation will be added in Task 3.