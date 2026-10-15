
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from mcp_server.tools import run_ai_analysis


@pytest.fixture
def scanner_finding():
    return {
        "file": "app.py",
        "line": 25,
        "vulnerability": "SQLi",
        "severity": "High",
        "confidence": 90,
        "code": "query = user_input",
    }


def test_mcp_tool_preserves_analysis_result(scanner_finding):
    expected_result = {
        "file": "app.py",
        "line": 25,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90.0,
        "risk_score": 77.62,
        "risk_level": "High",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-89",
        "ai_status": "completed",
        "explanation": "User-controlled input may affect a SQL query.",
        "impact": "An attacker may access or modify database data.",
        "recommendation": "Use parameterized queries.",
    }

    with patch(
        "mcp_server.tools.analyze_finding",
        return_value=expected_result,
    ) as mocked_analysis:
        result = run_ai_analysis(scanner_finding)

    assert result == expected_result
    mocked_analysis.assert_called_once()

    analyzed_input = mocked_analysis.call_args.args[0]
    assert analyzed_input["vulnerability"] == "SQLi"
    assert analyzed_input["confidence"] == 90.0
    assert analyzed_input["file"] == "app.py"


def test_mcp_tool_preserves_ai_failure_status(scanner_finding):
    expected_result = {
        "file": "app.py",
        "line": 25,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90.0,
        "risk_score": 77.62,
        "risk_level": "High",
        "owasp": "A03:2021 Injection",
        "cwe": "CWE-89",
        "ai_status": "failed",
        "explanation": None,
        "impact": None,
        "recommendation": "AI analysis service unavailable.",
    }

    with patch(
        "mcp_server.tools.analyze_finding",
        return_value=expected_result,
    ):
        result = run_ai_analysis(scanner_finding)

    assert result["ai_status"] == "failed"
    assert result["risk_score"] == 77.62
    assert result["risk_level"] == "High"
    assert result["owasp"] == "A03:2021 Injection"
    assert result["cwe"] == "CWE-89"
    assert result["explanation"] is None


def test_mcp_tool_rejects_invalid_confidence(scanner_finding):
    scanner_finding["confidence"] = 101

    with pytest.raises(ValidationError):
        run_ai_analysis(scanner_finding)


def test_mcp_tool_rejects_missing_required_field(scanner_finding):
    del scanner_finding["code"]

    with pytest.raises(KeyError):
        run_ai_analysis(scanner_finding)
