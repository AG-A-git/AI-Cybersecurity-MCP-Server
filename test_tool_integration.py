
# ======================================================
# MCP Tool Integration Test
# ======================================================

import json

from mcp_server.tools import analyze_scan


def main():
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

    print("\n===== MCP TOOL INTEGRATION TEST =====")
    print("Scanner findings:")
    print(json.dumps(findings, indent=2))

    try:
        results = analyze_scan(findings)
    except Exception as exc:
        print(f"Integration test failed: {type(exc).__name__}: {exc}")
        raise

    print("\n===== AI ANALYSIS RESULTS =====")
    print(json.dumps(results, indent=2, default=str))

    if results is None:
        raise AssertionError("analyze_scan returned None")

    print("\nMCP tool integration test passed.")


if __name__ == "__main__":
    main()
