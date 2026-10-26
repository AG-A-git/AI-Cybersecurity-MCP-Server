import logging

import pytest

from ai import batch
from ai.llm import generate_response


def test_generate_response_logs_no_exception_details(monkeypatch, caplog):
    secret_detail = "SENSITIVE_TOKEN_123"

    def fail_generate(self, prompt):
        raise RuntimeError(secret_detail)

    monkeypatch.setattr("ai.llm.OllamaClient.generate", fail_generate)

    with caplog.at_level(logging.WARNING, logger="ai.llm"):
        with pytest.raises(RuntimeError, match="Ollama request failed") as exc:
            generate_response("test prompt")

    assert "Ollama response generation failed" in caplog.text
    assert secret_detail not in caplog.text
    assert secret_detail not in str(exc.value)


def test_batch_failure_logs_no_exception_details(monkeypatch, caplog):
    secret_detail = "SENSITIVE_TOKEN_456"

    def fail_analysis(finding):
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(batch, "analyze_finding", fail_analysis)

    finding = {
        "finding_id": "finding-1",
        "file": "test.py",
        "line": 10,
        "code": "unsafe_input()",
        "vulnerability": "XSS",
        "severity": "High",
        "confidence": 90,
    }

    with caplog.at_level(logging.WARNING, logger="ai.batch"):
        results = batch.analyze_findings([finding])

    returned = results["results"]
    assert len(returned) == 1
    assert returned[0]["ai_status"] == "failed"
    assert "Batch AI analysis failed for one finding" in caplog.text
    assert secret_detail not in caplog.text
    assert secret_detail not in str(results)
