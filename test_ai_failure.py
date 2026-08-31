import json

import ai.llm as llm

from ai.models import VulnerabilityInput


# ======================================================
# Test scanner finding
# ======================================================

scanner_result = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


vulnerability = VulnerabilityInput(
    **scanner_result
)


# ======================================================
# Test 1: Ollama unavailable
# ======================================================

print("\n======================================")
print("TEST 1: OLLAMA UNAVAILABLE")
print("======================================")


# Save original URL
original_url = llm.OLLAMA_URL


# Use an invalid port to simulate Ollama being unavailable
llm.OLLAMA_URL = "http://127.0.0.1:59999/api/generate"


try:

    result = llm.analyze_vulnerability(
        vulnerability
    )

    print("\nResult:")
    print(
        json.dumps(
            result,
            indent=4
        )
    )


    # The application should NOT crash
    assert result is not None


    # AI should report failure
    assert result["ai_status"] == "failed"


    print("\nOLLAMA FAILURE HANDLED: PASSED")


finally:

    # Restore original URL
    llm.OLLAMA_URL = original_url


print("\n======================================")
print("TASK 8 TEST 1 PASSED")
print("======================================")
# ======================================================
# Test 2: Invalid AI JSON
# ======================================================

print("\n======================================")
print("TEST 2: INVALID AI JSON")
print("======================================")


original_generate_explanation = (
    llm.generate_explanation
)


def fake_invalid_ai_response(
    vulnerability_name,
    severity,
    confidence,
    file,
    line,
    code
):

    return "This is not valid JSON"


llm.generate_explanation = fake_invalid_ai_response


try:

    result = llm.analyze_vulnerability(
        vulnerability
    )

    print("\nResult:")
    print(
        json.dumps(
            result,
            indent=4
        )
    )


    assert result is not None

    assert result["ai_status"] == "failed"

    assert result["ai_analysis"] is None


    print(
        "\nINVALID JSON HANDLING: PASSED"
    )


finally:

    llm.generate_explanation = (
        original_generate_explanation
    )


print("\n======================================")
print("TASK 8 TEST 2 PASSED")
print("======================================")
# ======================================================
# Test 3: Missing AI fields
# ======================================================

print("\n======================================")
print("TEST 3: MISSING AI FIELDS")
print("======================================")


original_generate_explanation = (
    llm.generate_explanation
)


def fake_missing_fields(
    vulnerability_name,
    severity,
    confidence,
    file,
    line,
    code
):

    return """
    {
        "severity": "High",
        "risk_score": 90
    }
    """


llm.generate_explanation = fake_missing_fields


try:

    result = llm.analyze_vulnerability(
        vulnerability
    )

    print("\nResult:")
    print(
        json.dumps(
            result,
            indent=4
        )
    )


    assert result is not None

    assert result["ai_status"] == "failed"

    assert result["ai_analysis"] is None


    print(
        "\nMISSING FIELD HANDLING: PASSED"
    )


finally:

    llm.generate_explanation = (
        original_generate_explanation
    )


print("\n======================================")
print("TASK 8 TEST 3 PASSED")
print("======================================")
# ======================================================
# Test 4: AI timeout
# ======================================================

print("\n======================================")
print("TEST 4: AI TIMEOUT")
print("======================================")


original_generate = llm.OllamaClient.generate


def fake_timeout(self, prompt):

    raise RuntimeError(
        "Ollama request timed out."
    )


llm.OllamaClient.generate = fake_timeout


try:

    result = llm.analyze_vulnerability(
        vulnerability
    )

    print("\nResult:")
    print(
        json.dumps(
            result,
            indent=4
        )
    )


    assert result is not None

    assert result["ai_status"] == "failed"

    assert result["ai_analysis"] is None


    print(
        "\nTIMEOUT HANDLING: PASSED"
    )


finally:

    llm.OllamaClient.generate = (
        original_generate
    )


print("\n======================================")
print("TASK 8 TEST 4 PASSED")
print("======================================")