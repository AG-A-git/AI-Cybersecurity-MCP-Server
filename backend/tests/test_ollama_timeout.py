import sys
from pathlib import Path

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.llm import OllamaClient


def test_ollama_request_timeout_is_configured_and_reported(monkeypatch):
    def simulate_timeout(url, **kwargs):
        assert kwargs.get("timeout") == 120
        raise requests.exceptions.Timeout("Simulated Ollama timeout")

    monkeypatch.setattr("ai.llm.requests.post", simulate_timeout)

    client = OllamaClient()

    with pytest.raises(RuntimeError, match="Ollama request timed out"):
        client.generate("Test security analysis prompt")
