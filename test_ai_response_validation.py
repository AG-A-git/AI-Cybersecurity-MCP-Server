from pydantic import ValidationError

from ai.models import AIAnalysisResponse


# ==========================================
# TEST 1 — Valid AI response
# ==========================================

valid_response = {
    "severity": "High",
    "risk_score": 85,
    "owasp": "A03:2021 Injection",
    "cwe": "CWE-89",
    "explanation": "The code is vulnerable to SQL injection.",
    "recommendation": "Use parameterized queries or prepared statements."
}

try:
    result = AIAnalysisResponse(**valid_response)

    print("VALID RESPONSE: PASSED")
    print(result)

except ValidationError as e:

    print("VALID RESPONSE: FAILED")
    print(e)


# ==========================================
# TEST 2 — risk_score > 100
# ==========================================

invalid_high_score = {
    "severity": "High",
    "risk_score": 101,
    "owasp": "A03:2021 Injection",
    "cwe": "CWE-89",
    "explanation": "The code is vulnerable to SQL injection.",
    "recommendation": "Use parameterized queries."
}

try:
    AIAnalysisResponse(**invalid_high_score)

    print("SCORE > 100: FAILED")

except ValidationError:

    print("SCORE > 100: PASSED")


# ==========================================
# TEST 3 — risk_score < 0
# ==========================================

invalid_low_score = {
    "severity": "High",
    "risk_score": -1,
    "owasp": "A03:2021 Injection",
    "cwe": "CWE-89",
    "explanation": "The code is vulnerable to SQL injection.",
    "recommendation": "Use parameterized queries."
}

try:
    AIAnalysisResponse(**invalid_low_score)

    print("SCORE < 0: FAILED")

except ValidationError:

    print("SCORE < 0: PASSED")


# ==========================================
# TEST 4 — Missing field
# ==========================================

missing_cwe = {
    "severity": "High",
    "risk_score": 85,
    "owasp": "A03:2021 Injection",
    "explanation": "The code is vulnerable to SQL injection.",
    "recommendation": "Use parameterized queries."
}

try:
    AIAnalysisResponse(**missing_cwe)

    print("MISSING CWE: FAILED")

except ValidationError:

    print("MISSING CWE: PASSED")