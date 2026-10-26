from unittest.mock import Mock

import mcp_server.server as server_module


def test_registered_mcp_tool_passes_finding_to_analysis(monkeypatch):
    expected_result = {
        "file": "app.py",
        "line": 25,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90.0,
        "risk_score": 80,
        "risk_level": "High",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-89",
        "ai_status": "completed",
        "explanation": "Unsafe SQL query.",
        "impact": "Database data may be exposed.",
        "recommendation": "Use parameterized queries.",
    }

    mocked_analysis = Mock(return_value=expected_result)
    monkeypatch.setattr(
        server_module,
        "run_ai_analysis",
        mocked_analysis,
    )

    result = server_module.analyze_vulnerability_tool(
        file="app.py",
        line=25,
        vulnerability="SQLi",
        severity="High",
        confidence=90,
        code="query = user_input",
    )

    assert result == expected_result
    mocked_analysis.assert_called_once_with({
        "file": "app.py",
        "line": 25,
        "vulnerability": "SQLi",
        "severity": "High",
        "confidence": 90,
        "code": "query = user_input",
    })
