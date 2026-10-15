
import atexit
import json
import sys
import tempfile
from pathlib import Path

from scanner.engine import scan_project
from mcp_server.tools import analyze_scan


def main():
    print("\n======================================")
    print("STEP 1: PREPARING TEST PROJECT")
    print("======================================")

    # Keep test input separate from the main repository.
    temporary_project = tempfile.TemporaryDirectory(
        prefix="ai_cybersecurity_pipeline_"
    )
    atexit.register(temporary_project.cleanup)
    project_path = Path(temporary_project.name)

    target_file = project_path / "sql_test.py"

    # Deliberately vulnerable example for scanner testing.
    target_file.write_text(
        '''query = "SELECT * FROM users WHERE username='" + username + "'"\n''',
        encoding="utf-8",
    )

    print(f"Test file: {target_file.resolve()}")

    print("\n======================================")
    print("STEP 2: RUNNING SCANNER")
    print("======================================")

    try:
        findings = scan_project(str(project_path))
    except Exception as exc:
        print(f"Scanner failed: {type(exc).__name__}: {exc}")
        return 1

    if not isinstance(findings, list):
        print("FAILED: Scanner did not return a list.")
        return 1

    print(f"Scanner findings detected: {len(findings)}")
    print(json.dumps(findings, indent=2, default=str))

    if not findings:
        print("FAILED: Expected a finding from the test file.")
        return 1

    required_fields = {
        "file",
        "line",
        "vulnerability",
        "severity",
        "confidence",
        "code",
    }

    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            print(f"FAILED: Finding {index} is not a dictionary.")
            return 1

        missing = required_fields - finding.keys()
        if missing:
            print(
                f"FAILED: Finding {index} is missing fields: "
                f"{sorted(missing)}"
            )
            return 1

    print("\n======================================")
    print("STEP 3: RUNNING AI / MCP ANALYSIS")
    print("======================================")

    try:
        results = analyze_scan(findings)
    except Exception as exc:
        print(f"Analysis failed: {type(exc).__name__}: {exc}")
        return 1

    print("\n======================================")
    print("STEP 4: FINAL RESULTS")
    print("======================================")
    print(json.dumps(results, indent=2, default=str))

    if results is None:
        print("FAILED: Analysis returned None.")
        return 1

    # Accept either a list of results or a dictionary containing results.
    if isinstance(results, dict):
        analyzed_findings = results.get(
            "results",
            results.get("findings"),
        )

        # A single-result or aggregate dictionary may itself be the result.
        if analyzed_findings is None:
            analyzed_findings = [results]
    elif isinstance(results, list):
        analyzed_findings = results
    else:
        print(
            "FAILED: Unexpected analysis result type: "
            f"{type(results).__name__}"
        )
        return 1

    if not analyzed_findings:
        print("FAILED: Analysis returned no findings.")
        return 1

    if not all(isinstance(item, dict) for item in analyzed_findings):
        print("FAILED: Analysis contains an invalid finding.")
        return 1

    incomplete = [
        item for item in analyzed_findings
        if item.get("ai_status") != "completed"
    ]

    if incomplete:
        print("\n======================================")
        print("COMPLETE PIPELINE TEST: FAILED")
        print(
            f"AI analysis failed or was incomplete for "
            f"{len(incomplete)} finding(s)."
        )
        for item in incomplete:
            print(
                f"File: {item.get('file')}, "
                f"status: {item.get('ai_status', 'missing')}"
            )
        print("======================================")
        return 1

    print("\n======================================")
    print("COMPLETE PIPELINE TEST: PASSED")
    print("======================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
