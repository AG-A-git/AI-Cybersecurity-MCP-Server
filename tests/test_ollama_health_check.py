from unittest.mock import Mock, patch

import requests

from ai.llm import OllamaClient


def make_response(payload):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def make_client():
    return OllamaClient(
        url="http://localhost:11434/api/generate",
        model="test-model:latest",
        timeout=3.5,
    )


def test_health_check_returns_ok_when_model_is_available():
    response = make_response({
        "models": [{"name": "test-model:latest"}]
    })

    with patch("ai.llm.requests.get", return_value=response) as mock_get:
        client = make_client()
        result = client.health_check()

    assert result == "ok"
    mock_get.assert_called_once_with(
        "http://localhost:11434/api/tags",
        timeout=3.5,
    )


def test_health_check_reports_missing_model():
    response = make_response({
        "models": [{"name": "another-model:latest"}]
    })

    with patch("ai.llm.requests.get", return_value=response):
        result = make_client().health_check()

    assert result == "model_unavailable"


def test_health_check_handles_connection_refused():
    with patch(
        "ai.llm.requests.get",
        side_effect=requests.exceptions.ConnectionError("connection refused"),
    ):
        result = make_client().health_check()

    assert result == "unavailable"


def test_health_check_rejects_invalid_models_structure():
    response = make_response({"models": "not-a-list"})

    with patch("ai.llm.requests.get", return_value=response):
        result = make_client().health_check()

    assert result == "unavailable"


def test_health_check_handles_invalid_json():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("invalid JSON")

    with patch("ai.llm.requests.get", return_value=response):
        result = make_client().health_check()

    assert result == "unavailable"


def test_health_check_recovers_after_connection_failure():
    response = make_response({
        "models": [{"name": "test-model:latest"}]
    })

    with patch(
        "ai.llm.requests.get",
        side_effect=[
            requests.exceptions.ConnectionError("connection refused"),
            response,
        ],
    ) as mock_get:
        client = make_client()
        first_result = client.health_check()
        second_result = client.health_check()

    assert first_result == "unavailable"
    assert second_result == "ok"
    assert mock_get.call_count == 2
