
from unittest.mock import patch

from ai.analysis import analyze_vulnerability


def test_analyze_vulnerability():
    finding = {
        "file": "example.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
    }

    mock_ai_response = """
    {
        "explanation": "The application is vulnerable to SQL injection because user-controlled input is used in a database query.",
        "impact": "An attacker may manipulate the SQL query and access or modify sensitive database information.",
        "recommendation": "Use parameterized queries or prepared statements.",
        "secure_practice": "Always use parameterized queries when handling user-controlled database input."
    }
    """

    with patch(
        "ai.analysis.OllamaClient.generate",
        return_value=mock_ai_response,
    ):
        result = analyze_vulnerability(finding)

    # Verify scanner evidence is preserved
    assert result["file"] == "example.py"
    assert result["line"] == 10
    assert result["vulnerability"] == "SQL Injection"
    assert result["severity"] == "High"
    assert result["confidence"] == 90
    assert result["code"] == finding["code"]

    # Verify deterministic risk information is present
    assert "risk_score" in result
    assert isinstance(result["risk_score"], (int, float))
    assert 0 <= result["risk_score"] <= 100
    assert "risk_level" in result
    assert result["risk_level"] in {
        "Informational",
        "Low",
        "Medium",
        "High",
        "Critical",
    }

    # Verify vulnerability mapping
    assert "owasp" in result
    assert result["owasp"]
    assert "cwe" in result
    assert result["cwe"]

    # Verify AI analysis completed successfully
    assert result["ai_status"] == "completed"
    assert result["explanation"]
    assert result["impact"]
    assert result["recommendation"]
