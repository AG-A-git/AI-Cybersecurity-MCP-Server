# ======================================================
# Task 12 - Real Scanner + AI Integration Test
# ======================================================

import json

from ai.input import VulnerabilityInput
from ai.llm import analyze_vulnerability


# ======================================================
# Actual Scanner Finding
# ======================================================

scanner_finding = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


# ======================================================
# Print Scanner Finding
# ======================================================

print("\n===== SCANNER FINDING =====")

print(
    json.dumps(
        scanner_finding,
        indent=4
    )
)


# ======================================================
# Step 1 - Scanner Input Validation
# ======================================================

try:

    finding = VulnerabilityInput(
        **scanner_finding
    )

    print("\nSCANNER INPUT VALIDATION: PASSED")

except Exception as exc:

    print(
        "\nSCANNER INPUT VALIDATION: FAILED"
    )

    print(exc)

    raise SystemExit(1)


# ======================================================
# Step 2 - Run AI Security Analysis
# ======================================================

try:

    result = analyze_vulnerability(
        finding
    )

except Exception as exc:

    print(
        "\nAI ANALYSIS: FAILED"
    )

    print(exc)

    raise SystemExit(1)


# ======================================================
# Print AI Analysis
# ======================================================

print("\n===== AI ANALYSIS =====")

print(
    json.dumps(
        result,
        indent=4
    )
)


# ======================================================
# Step 3 - Verify Scanner Information
# ======================================================

assert result["file"] == "login.py"

assert result["line"] == 22

assert result["code"] == "cursor.execute(query)"

assert result["vulnerability"] == "SQL Injection"

assert result["severity"] == "Critical"

assert result["confidence"] == 95.0


# ======================================================
# Step 4 - Verify Risk Analysis
# ======================================================

assert (
    0 <= result["risk_score"] <= 100
), "Risk score must be between 0 and 100"


assert result["risk_level"] in {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational"
}


# ======================================================
# Step 5 - Verify OWASP / CWE
# ======================================================

assert (
    result["owasp"] ==
    "A03:2021 Injection"
)

assert (
    result["cwe"] ==
    "CWE-89"
)


# ======================================================
# Step 6 - Verify AI Status
# ======================================================

assert (
    result["ai_status"] ==
    "success"
), "AI analysis should succeed"


# ======================================================
# Step 7 - Verify AI Response
# ======================================================

assert (
    result["ai_analysis"] is not None
), "AI analysis should not be None"


ai_analysis = result["ai_analysis"]


assert (
    "severity" in ai_analysis
)

assert (
    "explanation" in ai_analysis
)

assert (
    "recommendation" in ai_analysis
)


# ======================================================
# Step 8 - Verify AI Does NOT Own Deterministic Data
# ======================================================

assert (
    "risk_score" not in ai_analysis
), "risk_score must be deterministic"


assert (
    "owasp" not in ai_analysis
), "OWASP must be deterministic"


assert (
    "cwe" not in ai_analysis
), "CWE must be deterministic"


# ======================================================
# Step 9 - Verify AI Content
# ======================================================

assert (
    isinstance(
        ai_analysis["explanation"],
        str
    )
)

assert (
    ai_analysis["explanation"].strip()
), "Explanation must not be empty"


assert (
    isinstance(
        ai_analysis["recommendation"],
        str
    )
)

assert (
    ai_analysis["recommendation"].strip()
), "Recommendation must not be empty"


# ======================================================
# Step 10 - Verify AI Severity
# ======================================================

assert (
    ai_analysis["severity"]
    in {
        "Critical",
        "High",
        "Medium",
        "Low"
    }
)


# ======================================================
# Final Result
# ======================================================

print(
    "\n=========================================="
)

print(
    "TASK 12 INTEGRATION TEST: PASSED"
)

print(
    "=========================================="
)

print(
    "\nVerified:"
)

print(
    "[✓] Scanner finding accepted"
)

print(
    "[✓] File preserved"
)

print(
    "[✓] Line preserved"
)

print(
    "[✓] Vulnerable code preserved"
)

print(
    "[✓] Vulnerability type preserved"
)

print(
    "[✓] Severity valid"
)

print(
    "[✓] Confidence valid"
)

print(
    "[✓] Risk score between 0 and 100"
)

print(
    "[✓] Risk level valid"
)

print(
    "[✓] OWASP mapping correct"
)

print(
    "[✓] CWE mapping correct"
)

print(
    "[✓] AI analysis successful"
)

print(
    "[✓] Explanation present"
)

print(
    "[✓] Recommendation present"
)

print(
    "[✓] AI does not control risk_score"
)

print(
    "[✓] AI does not control OWASP"
)

print(
    "[✓] AI does not control CWE"
)

print(
    "\nTask 12 completed successfully!"
)