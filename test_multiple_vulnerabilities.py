from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


# ======================================================
# Test vulnerabilities
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
    },

    {
        "file": "register.py",
        "line": 35,
        "vulnerability": "Input Validation",
        "severity": "Medium",
        "confidence": 80,
        "code": "age = request.form['age']"
    }

]


# ======================================================
# Run tests
# ======================================================

for index, scanner_result in enumerate(
    test_cases,
    start=1
):

    print("\n")
    print("=" * 60)

    print(
        f"TEST {index}: "
        f"{scanner_result['vulnerability']}"
    )

    print("=" * 60)

    # --------------------------------------------------
    # Convert scanner result into AI input model
    # --------------------------------------------------

    vulnerability = VulnerabilityInput(
        **scanner_result
    )

    # --------------------------------------------------
    # Analyze vulnerability
    # --------------------------------------------------

    result = analyze_vulnerability(
        vulnerability
    )

    # --------------------------------------------------
    # Display result
    # --------------------------------------------------

    print(
        "\nVulnerability:"
    )

    print(
        result["vulnerability"]
    )

    print(
        "\nSeverity:"
    )

    print(
        result["severity"]
    )

    print(
        "\nConfidence:"
    )

    print(
        result["confidence"]
    )

    print(
        "\nRisk Score:"
    )

    print(
        result["risk_score"]
    )

    print(
        "\nRisk Level:"
    )

    print(
        result["risk_level"]
    )

    print(
        "\nAI Status:"
    )

    print(
        result["ai_status"]
    )

    print(
        "\nExplanation:"
    )

    print(
        result["explanation"]
    )

    print(
        "\nRecommendation:"
    )

    print(
        result["recommendation"]
    )