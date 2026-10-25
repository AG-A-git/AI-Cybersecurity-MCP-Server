import json

from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


# ======================================================
# TASK 14: MULTIPLE VULNERABILITIES FINAL REPORT
# ======================================================

test_cases = [

    {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)"
    },

    {
        "file": "profile.js",
        "line": 18,
        "vulnerability": "XSS",
        "severity": "High",
        "confidence": 90,
        "code": "element.innerHTML = userInput"
    },

    {
        "file": "config.py",
        "line": 10,
        "vulnerability": "Hardcoded Credentials",
        "severity": "High",
        "confidence": 95,
        "code": "password = 'admin123'"
    }
]


print("\n======================================")
print("TASK 14: MULTIPLE VULNERABILITY REPORT")
print("======================================")


results = []


# ======================================================
# Analyze every vulnerability
# ======================================================

for index, scanner_result in enumerate(test_cases, start=1):

    print(
        f"\nAnalyzing vulnerability {index}: "
        f"{scanner_result['vulnerability']}"
    )

    vulnerability = VulnerabilityInput(
        **scanner_result
    )

    result = analyze_vulnerability(
        vulnerability
    )

    results.append(result)


# ======================================================
# Build report
# ======================================================

report = {
    "total_findings": len(results),
    "findings": results
}


# ======================================================
# Display report
# ======================================================

print("\n======================================")
print("FINAL REPORT")
print("======================================")

print(
    json.dumps(
        report,
        indent=2
    )
)


# ======================================================
# Save report
# ======================================================

with open(
    "multiple_vulnerability_report.json",
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        report,
        file,
        indent=2
    )


print("\n======================================")
print("TASK 14 COMPLETE")
print("======================================")

print(
    "Report saved to: "
    "multiple_vulnerability_report.json"
)