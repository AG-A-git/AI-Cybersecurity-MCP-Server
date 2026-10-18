
import pytest

from ai.response import AIAnalysis, parse_ai_response, extract_json_response


def valid_response():
    return {
        "explanation": "The application contains a security weakness.",
        "impact": "An attacker may exploit the weakness.",
        "recommendation": "Validate inputs and apply the appropriate security control.",
        "secure_practice": "Follow secure coding practices and review changes.",
    }


def test_valid_response():
    result = parse_ai_response(valid_response_as_json())

    assert isinstance(result, AIAnalysis)
    assert result.explanation
    assert result.impact
    assert result.recommendation
    assert result.secure_practice


def valid_response_as_json():
    import json

    return json.dumps(valid_response())


def test_markdown_json_response():
    import json

    response = f"```json\n{json.dumps(valid_response())}\n```"

    result = parse_ai_response(response)

    assert isinstance(result, AIAnalysis)
    assert result.explanation == valid_response()["explanation"]


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
    response = {
        "explanation": "Test explanation",
        "impact": "Test impact",
        "recommendation": "Test recommendation",
    }

    import json

    with pytest.raises(ValueError, match="missing or has invalid fields"):
        parse_ai_response(json.dumps(response))


def test_wrong_field_type():
    import json

    response = valid_response()
    response["explanation"] = 123

    with pytest.raises(ValueError, match="missing or has invalid fields"):
        parse_ai_response(json.dumps(response))


@pytest.mark.parametrize(
    "field",
    ["explanation", "impact", "recommendation", "secure_practice"],
)
def test_rejects_empty_required_fields(field):
    import json

    response = valid_response()
    response[field] = ""

    with pytest.raises(ValueError):
        parse_ai_response(json.dumps(response))


@pytest.mark.parametrize(
    "field",
    ["explanation", "impact", "recommendation", "secure_practice"],
)
def test_rejects_whitespace_only_required_fields(field):
    import json

    response = valid_response()
    response[field] = "   "

    with pytest.raises(ValueError):
        parse_ai_response(json.dumps(response))


def test_json_with_leading_explanatory_text():
    import json

    response = (
        "Here is the analysis:\n"
        + json.dumps(valid_response())
    )

    result = parse_ai_response(response)

    assert isinstance(result, AIAnalysis)


def test_json_with_trailing_explanatory_text():
    import json

    response = json.dumps(valid_response()) + "\nEnd of response."

    result = parse_ai_response(response)

    assert isinstance(result, AIAnalysis)
    assert result.explanation == valid_response()["explanation"]


def test_json_with_text_before_and_after_object():
    import json

    response = (
        "AI result follows:\n"
        + json.dumps(valid_response())
        + "\nEnd of response."
    )

    result = parse_ai_response(response)

    assert isinstance(result, AIAnalysis)


def test_recovers_missing_final_brace():
    import json

    response = json.dumps(valid_response())
    assert response.endswith("}")

    result = parse_ai_response(response[:-1])

    assert isinstance(result, AIAnalysis)


def test_extract_json_with_braces_inside_string():
    response = (
        '{"explanation":"A value containing { and } characters",'
        '"impact":"Test impact",'
        '"recommendation":"Test recommendation",'
        '"secure_practice":"Test secure practice"}'
    )

    result = parse_ai_response(response)

    assert result.explanation == "A value containing { and } characters"


def test_rejects_unrecoverable_truncated_json():
    response = (
        '{"explanation":"Test explanation",'
        '"impact":"Test impact",'
        '"recommendation":'
    )

    with pytest.raises(ValueError):
        parse_ai_response(response)


@pytest.mark.parametrize("response", [None, 123, [], {}])
def test_rejects_non_string_response(response):
    with pytest.raises(ValueError, match="must be a string"):
        extract_json_response(response)
