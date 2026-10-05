import requests

from pydantic import ValidationError

from ai.llm import classify_ai_error


def test_timeout_error():
    error = requests.exceptions.Timeout(
        "Ollama request timed out"
    )

    assert classify_ai_error(error) == "timeout"


def test_connection_error():
    error = requests.exceptions.ConnectionError(
        "Ollama is unavailable"
    )

    assert classify_ai_error(error) == "connection_error"


def test_request_error():
    error = requests.exceptions.RequestException(
        "Ollama request failed"
    )

    assert classify_ai_error(error) == "request_error"


def test_invalid_json_error():
    error = ValueError(
        "AI response contained invalid JSON"
    )

    assert classify_ai_error(error) == "invalid_json"


def test_invalid_response_error():
    error = ValueError(
        "Ollama response field is missing or invalid"
    )

    assert classify_ai_error(error) == "invalid_response"


def test_validation_error():
    try:
        raise ValidationError.from_exception_data(
            "TestModel",
            [],
        )
    except ValidationError as error:
        assert classify_ai_error(error) == "validation_error"


def test_unexpected_error():
    error = RuntimeError(
        "Unexpected AI failure"
    )

    assert classify_ai_error(error) == "unexpected_error"