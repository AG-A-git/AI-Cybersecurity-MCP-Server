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
