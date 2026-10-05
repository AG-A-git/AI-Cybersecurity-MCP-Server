from unittest.mock import Mock, patch

from ai.config import (
    OLLAMA_MODEL,
    OLLAMA_TEMPERATURE,
    OLLAMA_TOP_P,
    OLLAMA_NUM_CTX,
    OLLAMA_NUM_PREDICT,
)
from ai.llm import OllamaClient


def test_ollama_generation_parameters():
    """
    Verify that the Ollama client sends the configured
    generation parameters.
    """

    mock_response = Mock()

    mock_response.raise_for_status.return_value = None

    mock_response.json.return_value = {
        "response": (
            '{"explanation":"Test explanation",'
            '"recommendation":"Test recommendation",'
            '"owasp":"A03:2021 Injection",'
            '"cwe":"CWE-89"}'
        )
    }

    with patch(
        "ai.llm.requests.post",
        return_value=mock_response,
    ) as mock_post:

        client = OllamaClient()

        result = client.generate(
            "Analyze this security finding."
        )

    assert result

    mock_post.assert_called_once()

    call_kwargs = mock_post.call_args.kwargs

    payload = call_kwargs["json"]

    assert payload["model"] == OLLAMA_MODEL
    assert payload["stream"] is False
    assert payload["format"] == "json"

    options = payload["options"]

    assert options["temperature"] == OLLAMA_TEMPERATURE
    assert options["top_p"] == OLLAMA_TOP_P
    assert options["num_ctx"] == OLLAMA_NUM_CTX
    assert options["num_predict"] == OLLAMA_NUM_PREDICT


def test_ollama_client_rejects_empty_prompt():
    """
    Verify that an empty prompt is rejected before
    making an Ollama request.
    """

    client = OllamaClient()

    try:
        client.generate("")

        assert False, "Expected ValueError"

    except ValueError as exc:
        assert "prompt cannot be empty" in str(exc)


def test_ollama_client_rejects_non_string_prompt():
    """
    Verify that non-string prompts are rejected.
    """

    client = OllamaClient()

    try:
        client.generate(None)

        assert False, "Expected TypeError"

    except TypeError as exc:
        assert "prompt must be a string" in str(exc)