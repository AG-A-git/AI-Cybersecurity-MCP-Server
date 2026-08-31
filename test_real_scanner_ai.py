import json

from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


# ======================================================
# Temporary standardized scanner finding
# ======================================================
#
# IMPORTANT:
# This represents the format expected from Member 2.
# Replace this dictionary with the REAL scanner output
# when Member 2 provides it.
#

scanner_result = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


print("\n===== SCANNER FINDING =====")

print(
    json.dumps(
        scanner_result,
        indent=4
    )
)


# ======================================================
# Step 1: Validate scanner → AI contract
# ======================================================

try:

    vulnerability = VulnerabilityInput(
        **scanner_result
    )

    print(
        "\nSCANNER INPUT VALIDATION: PASSED"
    )

except Exception as e:

    print(
        "\nSCANNER INPUT VALIDATION: FAILED"
    )

    print(e)

    raise SystemExit(1)


# ======================================================
# Step 2: Send finding to AI
# ======================================================

try:

    result = analyze_vulnerability(
        vulnerability
    )

except Exception as e:

    print(
        "\nAI ANALYSIS: FAILED"
    )

    print(e)

    raise SystemExit(1)


# ======================================================
# Step 3: Display result
# ======================================================

print(
    "\n===== AI ANALYSIS ====="
)

print(
    json.dumps(
        result,
        indent=4
    )
)


# ======================================================
# Step 4: Task 7 verification
# ======================================================

assert (
    result["file"]
    == scanner_result["file"]
)

assert (
    result["line"]
    == scanner_result["line"]
)

assert (
    result["vulnerability"]
    == scanner_result["vulnerability"]
)

assert (
    result["severity"]
    == scanner_result["severity"]
)

assert (
    result["ai_status"]
    == "success"
)

assert (
    result["ai_analysis"]
    is not None
)

assert (
    result["ai_analysis"]["owasp"]
)

assert (
    result["ai_analysis"]["cwe"]
)

assert (
    result["ai_analysis"]["explanation"]
)

assert (
    result["ai_analysis"]["recommendation"]
)

assert (
    0 <= result["risk_score"] <= 100
)


print(
    "\n======================================"
)

print(
    "TASK 7 TEST PASSED"
)

print(
    "Scanner → AI integration successful"
)

print(
    "======================================"
)