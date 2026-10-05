from unittest.mock import patch

from ai.llm import OllamaClient
from ai.config import (
    OLLAMA_TEMPERATURE,
    OLLAMA_TOP_P,
    OLLAMA_NUM_CTX,
    OLLAMA_NUM_PREDICT,
)


class MockResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {
            "response": (
                '{"explanation":"Test explanation",'
                '"recommendation":"Test recommendation"}'
            )
        }


def test_repeated_generation_uses_identical_parameters():
    captured_payloads = []

    def mock_post(url, json, timeout):
        captured_payloads.append(json)
        return MockResponse()

    client = OllamaClient()

    with patch(
        "ai.llm.requests.post",
        side_effect=mock_post,
    ):
        first = client.generate("test security finding")
        second = client.generate("test security finding")

    assert first == second
    assert len(captured_payloads) == 2

    assert captured_payloads[0] == captured_payloads[1]

    options = captured_payloads[0]["options"]

    assert options["temperature"] == OLLAMA_TEMPERATURE
    assert options["top_p"] == OLLAMA_TOP_P
    assert options["num_ctx"] == OLLAMA_NUM_CTX
    assert options["num_predict"] == OLLAMA_NUM_PREDICT


def test_temperature_is_zero():
    assert OLLAMA_TEMPERATURE == 0.0