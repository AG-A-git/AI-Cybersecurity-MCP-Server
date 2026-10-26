import pytest

from ai.llm import normalize_ai_response
from ai.models import VulnerabilityInput


@pytest.fixture
def finding():
    return VulnerabilityInput(
        file="app.py",
        line=10,
        vulnerability="SQL Injection",
        severity="High",
        confidence=90,
        code="cursor.execute(query)",
    )


def test_accepts_valid_ai_response(finding):
    data = {
        "explanation": "User input reaches a database query.",
        "impact": "Unauthorized data access may be possible.",
        "recommendation": "Use parameterized SQL queries.",
        "owasp": "AI-supplied value",
        "cwe": "AI-supplied value",
    }

    result = normalize_ai_response(
        data,
        finding,
        expected_owasp="A03:2021 Injection",
        expected_cwe="CWE-89",
    )

    assert result.explanation == data["explanation"]
    assert result.recommendation == data["recommendation"]
    assert result.owasp == "A03:2021 Injection"
    assert result.cwe == "CWE-89"


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"explanation": "", "recommendation": "Fix it"},
        {"explanation": "   ", "recommendation": "Fix it"},
        {"explanation": "Valid explanation", "recommendation": ""},
        {"explanation": "Valid explanation", "recommendation": "   "},
        {"explanation": 123, "recommendation": "Fix it"},
        {"explanation": "Valid explanation", "recommendation": None},
    ],
)
def test_rejects_invalid_required_ai_fields(finding, data):
    with pytest.raises(ValueError):
        normalize_ai_response(data, finding)


def test_rejects_non_dictionary_ai_response(finding):
    with pytest.raises(ValueError, match="JSON object"):
        normalize_ai_response([], finding)


def test_missing_optional_impact_uses_model_default(finding):
    result = normalize_ai_response(
        {
            "explanation": "The query may be unsafe.",
            "recommendation": "Use parameterized queries.",
        },
        finding,
    )

    assert result.impact == ""