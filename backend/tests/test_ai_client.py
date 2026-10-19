import pytest
from services import ai_client


def test_ai_analysis_cannot_overwrite_scanner_fields(monkeypatch):
    scanner_finding = {
        "file": "src/app.py",
        "line": 42,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": "cursor.execute(query)",
    }

    def fake_analysis(finding):
        return {
            "file": "forged.py",
            "line": 999,
            "vulnerability": "Different vulnerability",
            "severity": "Low",
            "confidence": 10,
            "code": "forged code",
            "risk_score": 81,
            "explanation": "Test enrichment",
        }

    monkeypatch.setattr(
        ai_client,
        "analyze_vulnerability",
        fake_analysis,
    )

    results = ai_client.analyze_vulnerabilities(
        [scanner_finding]
    )

    assert len(results) == 1
    result = results[0]

    assert result["file"] == "src/app.py"
    assert result["line"] == 42
    assert result["vulnerability"] == "SQL Injection"
    assert result["severity"] == "High"
    assert result["confidence"] == 90
    assert result["code"] == "cursor.execute(query)"

    assert result["risk_score"] == 81
    assert result["explanation"] == "Test enrichment"



def test_ai_input_must_be_a_list():
    with pytest.raises(
        ValueError,
        match="AI input must be a list",
    ):
        ai_client.analyze_vulnerabilities(None)


def test_ai_input_findings_must_be_dictionaries():
    with pytest.raises(
        ValueError,
        match="AI input finding at index 0 must be a dictionary",
    ):
        ai_client.analyze_vulnerabilities([None])

def test_invalid_ai_response_uses_scanner_fallback(monkeypatch):
    monkeypatch.setattr(
        ai_client,
        "analyze_vulnerability",
        lambda finding: None,
    )

    finding = {
        "file": "src/app.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": "cursor.execute(query)",
    }

    result = ai_client.analyze_vulnerabilities([finding])[0]

    assert result["file"] == finding["file"]
    assert result["line"] == finding["line"]
    assert result["severity"] == finding["severity"]
    assert result["confidence"] == finding["confidence"]
    assert result["code"] == finding["code"]
    assert result["risk_score"] == 67.5
    assert result["owasp"] == "A03:2021 Injection"
    assert result["cwe"] == "CWE-89"
    assert result["explanation"] is None
    assert result["impact"] is None
    assert result["recommendation"] is None

def test_ai_analysis_exception_uses_scanner_fallback(monkeypatch):
    def fail_analysis(finding):
        raise RuntimeError("AI service unavailable")

    monkeypatch.setattr(
        ai_client,
        "analyze_vulnerability",
        fail_analysis,
    )

    finding = {
        "file": "src/app.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": "cursor.execute(query)",
    }

    results = ai_client.analyze_vulnerabilities([finding])

    assert len(results) == 1
    assert results[0]["file"] == "src/app.py"
    assert results[0]["severity"] == "High"
    assert results[0]["risk_score"] == 67.5
    assert results[0]["explanation"] is None
