import pytest
from ai.response import AIAnalysis, parse_ai_response


def test_valid_response():
    response = """
    {
        "explanation": "The application is vulnerable to cross-site scripting.",
        "impact": "An attacker may execute malicious JavaScript in a victim's browser.",
        "recommendation": "Escape untrusted output before rendering it.",
        "secure_practice": "Use context-aware output encoding and a secure templating framework."
    }
    """

    result = parse_ai_response(response)

    assert isinstance(result, AIAnalysis)
    assert result.explanation
    assert result.impact
    assert result.recommendation
    assert result.secure_practice


def test_markdown_json_response():
    response = """```json
{
    "explanation": "Test explanation",
    "impact": "Test impact",
    "recommendation": "Test recommendation",
    "secure_practice": "Test secure practice"
}
```"""

    result = parse_ai_response(response)

    assert isinstance(result, AIAnalysis)
    assert result.explanation == "Test explanation"


def test_empty_response():
    with pytest.raises(ValueError, match="empty response"):
        parse_ai_response("")


def test_invalid_json():
    with pytest.raises(ValueError, match="invalid JSON"):
        parse_ai_response("{invalid json}")


def test_non_object_json():
    with pytest.raises(ValueError, match="JSON object"):
        parse_ai_response('["not", "an", "object"]')


def test_missing_required_field():
    response = """
    {
        "explanation": "Test explanation",
        "impact": "Test impact",
        "recommendation": "Test recommendation"
    }
    """

    with pytest.raises(ValueError, match="missing or has invalid fields"):
        parse_ai_response(response)


def test_wrong_field_type():
    response = """
    {
        "explanation": 123,
        "impact": "Test impact",
        "recommendation": "Test recommendation",
        "secure_practice": "Test secure practice"
    }
    """

    with pytest.raises(ValueError, match="missing or has invalid fields"):
        parse_ai_response(response)
