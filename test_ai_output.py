
from unittest.mock import patch

from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


def test_ai_output():
    scanner_result = {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95,
        "code": "cursor.execute(query)",
    }

    vulnerability = VulnerabilityInput(**scanner_result)

    expected_result = {
        "file": "login.py",
        "line": 22,
        "code": "cursor.execute(query)",
        "vulnerability": "SQL Injection",
        "severity": "Critical",
        "confidence": 95.0,
        "risk_score": 95.0,
        "risk_level": "Critical",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-89",
        "ai_status": "completed",
        "ai_analysis": {
            "explanation": (
                "User input reaches a SQL query without safe parameterization."
            ),
            "recommendation": (
                "Use parameterized queries and avoid building SQL "
                "with string concatenation."
            ),
        },
        "recommendation": (
            "Use parameterized queries and avoid building SQL "
            "with string concatenation."
        ),
    }

    # Patch the lower-level dependency so the real implementation
    # runs without making a live Ollama request.
    with patch(
        "ai.llm.OllamaClient.generate",
        return_value=(
            '{"explanation":"User input reaches a SQL query '
            'without safe parameterization.",'
            '"recommendation":"Use parameterized queries and avoid '
            'building SQL with string concatenation."}'
        ),
    ):
        result = analyze_vulnerability(vulnerability)

    assert result is not None
    assert result["file"] == expected_result["file"]
    assert result["line"] == expected_result["line"]
    assert result["vulnerability"] == expected_result["vulnerability"]
    assert result["severity"] == expected_result["severity"]
    assert result["confidence"] == expected_result["confidence"]
    assert result["ai_status"] == expected_result["ai_status"]
    assert result["ai_analysis"]["explanation"]
    assert result["ai_analysis"]["recommendation"]
