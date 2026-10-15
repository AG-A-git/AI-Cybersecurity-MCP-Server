import mcp_server as api_module
from fastapi.testclient import TestClient


client = TestClient(api_module.app)


def scanner_payload():
    return {
        "file": "login.py",
        "line": 22,
        "vulnerability": "SQLi",
        "severity": "High",
        "confidence": 90,
        "code": "cursor.execute(query)",
    }


def make_analysis(finding, status="completed", owasp="A03:2021 Injection",
                  cwe="CWE-89"):
    return {
        "file": finding["file"],
        "line": finding["line"],
        "code": finding["code"],
        "vulnerability": "SQL Injection",
        "severity": finding["severity"],
        "confidence": finding["confidence"],
        "risk_score": 77.62,
        "risk_level": "High",
        "owasp": owasp,
        "cwe": cwe,
        "ai_status": status,
        "explanation": (
            "User-controlled input may affect a SQL query."
            if status == "completed"
            else None
        ),
        "impact": (
            "An attacker may access or modify database data."
            if status == "completed"
            else None
        ),
        "recommendation": (
            "Use parameterized queries."
            if status == "completed"
            else "AI analysis service unavailable."
        ),
    }


def test_api_analyze_preserves_evidence_and_analysis_fields(monkeypatch):
    seen = {}

    def fake_analyze(finding):
        seen.update(finding)
        return make_analysis(finding)

    monkeypatch.setattr(api_module, "analyze_finding", fake_analyze)

    payload = scanner_payload()
    response = client.post("/analyze", json=payload)

    assert response.status_code == 200
    result = response.json()

    # The endpoint passes the supplied scanner evidence to analysis.
    assert seen["file"] == payload["file"]
    assert seen["line"] == payload["line"]
    assert seen["code"] == payload["code"]
    assert seen["vulnerability"] == payload["vulnerability"]

    # The API returns the established response contract.
    assert result["file"] == payload["file"]
    assert result["line"] == payload["line"]
    assert result["code"] == payload["code"]
    assert result["vulnerability"] == "SQL Injection"
    assert result["severity"] == "High"
    assert result["confidence"] == 90
    assert result["risk_score"] == 77.62
    assert result["risk_level"] == "High"
    assert result["owasp"] == "A03:2021 Injection"
    assert result["cwe"] == "CWE-89"
    assert result["ai_status"] == "completed"
    assert result["explanation"]
    assert result["recommendation"] == "Use parameterized queries."


def test_api_analyze_reports_ai_failure_without_fake_analysis(monkeypatch):
    def fake_analyze(finding):
        return make_analysis(finding, status="failed")

    monkeypatch.setattr(api_module, "analyze_finding", fake_analyze)

    response = client.post("/analyze", json=scanner_payload())

    assert response.status_code == 200
    result = response.json()
    assert result["ai_status"] == "failed"
    assert result["explanation"] is None
    assert result["impact"] is None
    assert result["recommendation"] == "AI analysis service unavailable."
    assert result["file"] == "login.py"
    assert result["code"] == "cursor.execute(query)"
    assert result["risk_score"] == 77.62


def test_api_analyze_accepts_unknown_owasp_and_cwe(monkeypatch):
    def fake_analyze(finding):
        return make_analysis(finding, owasp="Unknown", cwe="Unknown")

    monkeypatch.setattr(api_module, "analyze_finding", fake_analyze)

    response = client.post("/analyze", json=scanner_payload())

    assert response.status_code == 200
    result = response.json()
    assert result["owasp"] == "Unknown"
    assert result["cwe"] == "Unknown"
