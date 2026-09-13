import json

from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


def test_ai_output():
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

    print("\n======================================")
    print("TASK 9: AI OUTPUT VALIDATION")
    print("======================================")

    result = analyze_vulnerability(
        vulnerability
    )

    print("\n===== FINAL AI OUTPUT =====")
    print(
        json.dumps(
            result,
            indent=4
        )
    )

    required_fields = [
        "file",
        "line",
        "code",
        "vulnerability",
        "severity",
        "confidence",
        "risk_score",
        "risk_level",
        "owasp",
        "cwe",
        "ai_status",
        "ai_analysis",
        "recommendation"
    ]

    print("\n===== OUTPUT VALIDATION =====")

    for field in required_fields:
        if field in result:
            print(f"{field}: OK")
        else:
            print(f"{field}: MISSING")

    assert result is not None

    for field in required_fields:
        assert field in result, f"Missing field: {field}"

    print("\nTASK 9: PASSED")


if __name__ == "__main__":
    test_ai_output()