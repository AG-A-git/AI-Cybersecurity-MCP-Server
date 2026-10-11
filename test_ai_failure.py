import pytest
from unittest.mock import patch

import ai.llm as llm
from ai.models import VulnerabilityInput


@pytest.fixture
def vulnerability():
    return VulnerabilityInput(
        file="login.py",
        line=22,
        vulnerability="SQL Injection",
        severity="Critical",
        confidence=95,
        code="cursor.execute(query)",
    )


@pytest.mark.parametrize(
    ("fake_response", "expected_error"),
    [
        (RuntimeError("Connection refused"), "unexpected_error"),
        ("This is not valid JSON", "invalid_json"),
        ('{"unexpected_field": "value"}', "invalid_response"),
        (RuntimeError("Ollama request timed out"), "unexpected_error"),
    ],
    ids=[
        "connection-refused-runtime-error",
        "invalid-json",
        "missing-ai-fields",
        "timeout-runtime-error",
    ],
)
def test_ai_failure_classification(
    vulnerability, fake_response, expected_error
):
    if isinstance(fake_response, Exception):
        with patch(
            "ai.llm.OllamaClient.generate",
            side_effect=fake_response,
        ):
            result = llm.analyze_vulnerability(vulnerability)
    else:
        with patch(
            "ai.llm.OllamaClient.generate",
            return_value=fake_response,
        ):
            result = llm.analyze_vulnerability(vulnerability)

    assert result["ai_status"] == "failed"
    assert result["ai_error_type"] == expected_error
    assert result["ai_analysis"] is None
    assert result["severity"] == "Critical"
    assert result["confidence"] == 95
    assert result["risk_score"] == 95
    assert result["recommendation"]
