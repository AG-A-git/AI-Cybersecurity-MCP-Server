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