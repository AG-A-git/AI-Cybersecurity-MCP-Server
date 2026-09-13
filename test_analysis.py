from unittest.mock import patch

from ai.analysis import analyze_vulnerability


def test_analyze_vulnerability():
    finding = {
        "file": "example.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)'
    }

    mock_ai_response = """
    {
        "explanation": "The application is vulnerable to SQL injection because user-controlled input is used in a database query.",
        "impact": "An attacker may manipulate the SQL query and access or modify sensitive database information.",
        "recommendation": "Use parameterized queries or prepared statements.",
        "secure_practice": "Always use parameterized queries when handling user-controlled database input."
    }
    """

    with patch("ai.analysis.OllamaClient.generate", return_value=mock_ai_response):
        result = analyze_vulnerability(finding)

    assert result["file"] == "example.py"
    assert result["line"] == 10
    assert result["vulnerability"] == "SQL Injection"
    assert result["severity"] == "High"
    assert result["confidence"] == 90

    assert "risk_score" in result
    assert "owasp" in result
    assert "cwe" in result

    assert result["explanation"]
    assert result["impact"]
    assert result["recommendation"]