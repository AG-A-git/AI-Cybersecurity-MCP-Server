
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
    "code": "cursor.execute(query)",
}


# ======================================================
# Print Scanner Finding
# ======================================================

print("\n===== SCANNER FINDING =====")
print(json.dumps(scanner_finding, indent=4))


# ======================================================
# Step 1 - Scanner Input Validation
# ======================================================

try:
    finding = VulnerabilityInput(**scanner_finding)
    print("\nSCANNER INPUT VALIDATION: PASSED")

except Exception as exc:
    print("\nSCANNER INPUT VALIDATION: FAILED")
    print(exc)
    raise SystemExit(1)


# ======================================================
# Step 2 - Run AI Security Analysis
# ======================================================

try:
    result = analyze_vulnerability(finding)

except Exception as exc:
    print("\nAI ANALYSIS: FAILED")
    print(exc)
    raise SystemExit(1)


# ======================================================
# Print AI Analysis
# ======================================================

print("\n===== AI ANALYSIS =====")
print(json.dumps(result, indent=4))


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

assert 0 <= result["risk_score"] <= 100, (
    "Risk score must be between 0 and 100"
)

assert result["risk_level"] in {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
}


# ======================================================
# Step 5 - Verify OWASP / CWE
# ======================================================

assert result["owasp"] == "A03:2021 Injection"
assert result["cwe"] == "CWE-89"


# ======================================================
# Step 6 - Verify AI Status
# ======================================================

assert result["ai_status"] == "completed", (
    "AI analysis should complete successfully"
)


# ======================================================
# Step 7 - Verify AI Response
# ======================================================

ai_analysis = result["ai_analysis"]

assert ai_analysis is not None, (
    "AI analysis should not be None"
)

assert isinstance(ai_analysis["explanation"], str)
assert ai_analysis["explanation"].strip(), (
    "Explanation must not be empty"
)

assert isinstance(ai_analysis["recommendation"], str)
assert ai_analysis["recommendation"].strip(), (
    "Recommendation must not be empty"
)


# ======================================================
# Step 8 - Verify Deterministic Data
# ======================================================

assert "risk_score" not in ai_analysis, (
    "risk_score must remain deterministic"
)

# OWASP and CWE are present in the current AIAnalysisResponse
# model, so validate their authoritative top-level values.
assert result["owasp"] == "A03:2021 Injection"
assert result["cwe"] == "CWE-89"


# ======================================================
# Final Result
# ======================================================

print("\n==========================================")
print("TASK 12 INTEGRATION TEST: PASSED")
print("==========================================")

print("\nVerified:")
print("[✓] Scanner finding accepted")
print("[✓] File preserved")
print("[✓] Line preserved")
print("[✓] Vulnerable code preserved")
print("[✓] Vulnerability type preserved")
print("[✓] Severity preserved")
print("[✓] Confidence preserved")
print("[✓] Risk score between 0 and 100")
print("[✓] Risk level valid")
print("[✓] OWASP mapping correct")
print("[✓] CWE mapping correct")
print("[✓] AI analysis completed")
print("[✓] Explanation present")
print("[✓] Recommendation present")
print("[✓] Risk score remains deterministic")

print("\nTask 12 completed successfully!")
