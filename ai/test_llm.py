import pytest

from .llm import generate_response


def test_generate_response():
    prompt = "Explain SQL injection in one sentence."

    try:
        response = generate_response(prompt)

        assert response is not None
        assert isinstance(response, str)
        assert len(response.strip()) > 0

    except RuntimeError as exc:
        # Skip instead of failing when Ollama is unavailable
        pytest.skip(str(exc))