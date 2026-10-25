import json

import ai.llm as llm
from ai.models import VulnerabilityInput


scanner_result = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)",
}

vulnerability = VulnerabilityInput(**scanner_result)


def run_failure_test(title, fake_response, expected_error):
    print("\n" + "=" * 38)
    print(title)
    print("=" * 38)

    original_generate = llm.OllamaClient.generate

    def fake_generate(self, prompt):
        if isinstance(fake_response, Exception):
            raise fake_response
        return fake_response

    llm.OllamaClient.generate = fake_generate

    try:
        result = llm.analyze_vulnerability(vulnerability)

        print(json.dumps(result, indent=4))

        assert result is not None, "Result should not be None"
        assert result["ai_status"] == "failed", (
            f"Expected failed status, got {result['ai_status']}"
        )
        assert result["ai_analysis"] is None, (
            "Failed analysis should not contain AI analysis"
        )

        if expected_error:
            assert result["ai_error_type"] == expected_error, (
                f"Expected {expected_error}, "
                f"got {result.get('ai_error_type')}"
            )

        print(f"\n{title}: PASSED")

    finally:
        llm.OllamaClient.generate = original_generate


# Test 1: Ollama unavailable
run_failure_test(
    "TEST 1: OLLAMA UNAVAILABLE",
    RuntimeError("Connection refused"),
"unexpected_error",
)

# Test 2: Invalid AI JSON
run_failure_test(
    "TEST 2: INVALID AI JSON",
    "This is not valid JSON",
    "invalid_json",
)

# Test 3: Missing AI fields
run_failure_test(
    "TEST 3: MISSING AI FIELDS",
    '{"unexpected_field": "value"}',
"invalid_response",
)

# Test 4: AI timeout / request failure
run_failure_test(
    "TEST 4: AI REQUEST FAILURE",
    RuntimeError("Ollama request timed out"),
"unexpected_error",
)

print("\n" + "=" * 38)
print("AI FAILURE TESTS FINISHED")
print("=" * 38)