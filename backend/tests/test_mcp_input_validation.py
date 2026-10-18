import pytest

import services.mcp_server as mcp_server


VALID_FINDING = {
    "file": "app.py",
    "line": 12,
    "vulnerability": "SQL Injection",
    "severity": "High",
    "confidence": 90,
    "code": "cursor.execute(query)",
}


def test_analyze_rejects_non_list_before_ai(monkeypatch):
    ai = lambda findings: pytest.fail("AI must not be called")
    monkeypatch.setattr(mcp_server, "analyze_vulnerabilities", ai)

    with pytest.raises(ValueError, match="Findings must be a list"):
        mcp_server.analyze_vulnerability(findings="not a list")


def test_analyze_rejects_too_many_findings_before_ai(monkeypatch):
    ai = lambda findings: pytest.fail("AI must not be called")
    monkeypatch.setattr(mcp_server, "analyze_vulnerabilities", ai)

    with pytest.raises(ValueError, match="Too many findings"):
        mcp_server.analyze_vulnerability(
            findings=[VALID_FINDING] * (mcp_server.MAX_AI_FINDINGS + 1)
        )


def test_analyze_rejects_non_dictionary_finding_before_ai(monkeypatch):
    ai = lambda findings: pytest.fail("AI must not be called")
    monkeypatch.setattr(mcp_server, "analyze_vulnerabilities", ai)

    with pytest.raises(ValueError, match="must be a dictionary"):
        mcp_server.analyze_vulnerability(findings=["not a finding"])


def test_analyze_rejects_missing_required_fields_before_ai(monkeypatch):
    ai = lambda findings: pytest.fail("AI must not be called")
    monkeypatch.setattr(mcp_server, "analyze_vulnerabilities", ai)

    with pytest.raises(ValueError, match="missing required fields"):
        mcp_server.analyze_vulnerability(
            findings=[{"file": "app.py"}]
        )


@pytest.mark.parametrize(
    "bad_value",
    [
        {"code": object()},
        {"confidence": float("nan")},
    ],
)
def test_analyze_rejects_non_json_values_before_ai(monkeypatch, bad_value):
    ai = lambda findings: pytest.fail("AI must not be called")
    monkeypatch.setattr(mcp_server, "analyze_vulnerabilities", ai)

    finding = {**VALID_FINDING, **bad_value}

    with pytest.raises(ValueError, match="valid JSON-compatible values"):
        mcp_server.analyze_vulnerability(findings=[finding])


def test_analyze_rejects_oversized_input_before_ai(monkeypatch):
    ai = lambda findings: pytest.fail("AI must not be called")
    monkeypatch.setattr(mcp_server, "analyze_vulnerabilities", ai)

    finding = {
        **VALID_FINDING,
        "code": "x" * (mcp_server.MAX_AI_INPUT_BYTES + 1),
    }

    with pytest.raises(ValueError, match="256 KiB size limit"):
        mcp_server.analyze_vulnerability(findings=[finding])
