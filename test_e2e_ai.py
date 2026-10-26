# ======================================================
# End-to-End AI Security Test
# ======================================================

import json

from mcp_server.tools import analyze_scan


def main():
    print("\n==============================")
    print("END-TO-END AI SECURITY TEST")
    print("==============================")

    # --------------------------------------------------
    # Scanner findings used for the integration test
    # --------------------------------------------------

    findings = [
        {
            "file": "login.py",
            "line": 22,
            "vulnerability": "SQL Injection",
            "severity": "Critical",
            "confidence": 95,
            "code": "cursor.execute(query)",
        },
        {
            "file": "profile.html",
            "line": 15,
            "vulnerability": "XSS",
            "severity": "High",
            "confidence": 91,
            "code": "element.innerHTML = user_input",
        },
    ]

    print("\n===== SCANNER FINDINGS =====")
    print(json.dumps(findings, indent=4))

    # --------------------------------------------------
    # Run the end-to-end AI analysis
    # --------------------------------------------------

    try:
        results = analyze_scan(findings)
    except Exception as exc:
        print("\nEND-TO-END AI ANALYSIS FAILED")
        print(f"{type(exc).__name__}: {exc}")
        raise

    # --------------------------------------------------
    # Normalize the result for display
    # --------------------------------------------------

    if isinstance(results, dict):
        results_to_check = results.get("results", results)
    else:
        results_to_check = results

    print("\n===== END-TO-END RESULTS =====")
    print(json.dumps(results, indent=4, default=str))

    # --------------------------------------------------
    # Verify result structure
    # --------------------------------------------------

    assert results is not None, "Analysis returned no results"

    if isinstance(results_to_check, list):
        assert len(results_to_check) == len(findings), (
            "Expected one analysis result per scanner finding"
        )

        for index, result in enumerate(results_to_check):
            assert isinstance(result, dict), (
                f"Result {index} must be a dictionary"
            )

            assert result.get("severity") == findings[index]["severity"], (
                f"Scanner severity changed for finding {index}"
            )

            assert result.get("confidence") == float(
                findings[index]["confidence"]
            ), f"Scanner confidence changed for finding {index}"

            assert result.get("file") == findings[index]["file"]
            assert result.get("vulnerability") == findings[index]["vulnerability"]

    elif isinstance(results_to_check, dict):
        # Some implementations wrap results in a dictionary.
        # Validate scanner-owned fields if the wrapper contains one finding.
        if "severity" in results_to_check:
            assert results_to_check["severity"] == findings[0]["severity"]

        if "confidence" in results_to_check:
            assert results_to_check["confidence"] == float(
                findings[0]["confidence"]
            )

    else:
        raise AssertionError(
            f"Unexpected analysis result type: {type(results).__name__}"
        )

    print("\n==========================================")
    print("END-TO-END AI SECURITY TEST: PASSED")
    print("==========================================")


# Only execute the integration test when run directly.
# Pytest can import this file without contacting Ollama.
if __name__ == "__main__":
    main()
