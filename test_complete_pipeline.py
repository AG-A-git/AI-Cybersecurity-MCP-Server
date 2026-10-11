
# ======================================================
# Complete Cybersecurity AI Pipeline Integration Test
# ======================================================

import json
import sys
from pathlib import Path

from mcp_server.tools import analyze_scan


def main():
    print("\n======================================")
    print("STEP 1: RUNNING MEMBER 2 SCANNER")
    print("======================================")

    # Import and execute the scanner only when this script
    # is run directly, not when pytest imports this module.
    try:
        from scanner.scanner import scan_file  # Adjust if your scanner uses a different module.
    except ImportError as exc:
        print(f"Could not import scanner: {exc}")
        print(
            "Update the scanner import to match your project's "
            "actual scanner module."
        )
        return 1

    target_file = Path("sql_test.py")

    if not target_file.exists():
        target_file.write_text(
            '''query = "SELECT * FROM users WHERE username='" + username + "'"\\n''',
            encoding="utf-8",
        )
        print(f"Created sample file: {target_file}")

    try:
        findings = scan_file(str(target_file))
    except Exception as exc:
        print(f"Scanner failed: {type(exc).__name__}: {exc}")
        return 1

    print(f"\nScanner findings detected: {len(findings)}")

    print("\n======================================")
    print("STEP 2: SCANNER JSON")
    print("======================================")
    print(json.dumps(findings, indent=2, default=str))

    if not findings:
        print("No findings detected; there is nothing to analyze.")
        return 0

    print("\n======================================")
    print("STEP 3: AI ANALYSIS")
    print("======================================")

    try:
        results = analyze_scan(findings)
    except Exception as exc:
        print(f"AI analysis failed: {type(exc).__name__}: {exc}")
        return 1

    print("\n======================================")
    print("STEP 4: FINAL RESULTS")
    print("======================================")
    print(json.dumps(results, indent=2, default=str))

    # Verify the pipeline returned a usable result.
    if results is None:
        print("FAILED: Pipeline returned None.")
        return 1

    print("\n======================================")
    print("COMPLETE PIPELINE TEST: PASSED")
    print("======================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
