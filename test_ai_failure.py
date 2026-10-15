
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


def test_failure_followed_by_success_is_isolated(vulnerability):
    successful_response = (
        '{"explanation":"Hardcoded credential finding",'
        '"recommendation":"Load credentials from a secure secret store"}'
    )

    next_vulnerability = VulnerabilityInput(
        file="profile.py",
        line=41,
        vulnerability="Hardcoded Credentials",
        severity="Low",
        confidence=70,
        code='password = "example"',
    )

    with patch(
        "ai.llm.OllamaClient.generate",
        side_effect=[
            RuntimeError("Connection refused"),
            successful_response,
        ],
    ) as mock_generate:
        failed_result = llm.analyze_vulnerability(vulnerability)
        successful_result = llm.analyze_vulnerability(next_vulnerability)

    # The first finding fails safely and preserves its scanner metadata.
    assert failed_result["ai_status"] == "failed"
    assert failed_result["ai_analysis"] is None
    assert failed_result["file"] == "login.py"
    assert failed_result["severity"] == "Critical"
    assert failed_result["confidence"] == 95
    assert failed_result["risk_score"] == 95

    # The next finding succeeds with its own scanner metadata and AI output.
    assert successful_result["ai_status"] == "completed"
    assert successful_result["file"] == "profile.py"
    assert successful_result["line"] == 41
    assert successful_result["vulnerability"] == "Hardcoded Credentials"
    assert successful_result["severity"] == "Low"
    assert successful_result["confidence"] == 70
    assert successful_result["risk_score"] == 28
    assert successful_result["ai_analysis"]["explanation"] == (
        "Hardcoded credential finding"
    )
    assert successful_result["recommendation"] == (
        "Load credentials from a secure secret store"
    )

    assert mock_generate.call_count == 2
