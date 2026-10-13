
from ai.batch import generate_report


def test_generate_report_handles_multiple_findings(monkeypatch):
    def fake_generate(prompt):
        return """
        {
            "explanation": "Test explanation.",
            "impact": "Test impact.",
            "recommendation": "Test recommendation.",
            "secure_practice": "Use secure coding practices."
        }
        """

    class FakeClient:
        def generate(self, prompt):
            return fake_generate(prompt)

    monkeypatch.setattr(
        "ai.analysis.OllamaClient",
        lambda: FakeClient()
    )

    findings = [
        {
            "file": "a.py",
            "line": 10,
            "vulnerability": "SQL Injection",
            "severity": "High",
            "confidence": 90,
            "code": "query = user_input"
        },
        {
            "file": "b.py",
            "line": 20,
            "vulnerability": "XSS",
            "severity": "Medium",
            "confidence": 85,
            "code": "innerHTML = user_input"
        },
        {
            "file": "c.py",
            "line": 30,
            "vulnerability": "Hardcoded Credentials",
            "severity": "High",
            "confidence": 95,
            "code": "password = 'admin123'"
        }
    ]

    report = generate_report(
        findings,
        project="test-project"
    )

    assert report["project"] == "test-project"
    assert report["total_findings"] == 3
    assert report["successful_analyses"] == 3
    assert report["failed_analyses"] == 0
    assert len(report["findings"]) == 3

def test_generate_report_preserves_finding_order_and_types(monkeypatch):
    from ai.batch import analyze_findings

    def fake_analyze(finding):
        return {
            "file": finding["file"],
            "line": finding["line"],
            "vulnerability": finding["vulnerability"],
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "risk_score": 60.0,
            "risk_level": "Medium",
            "ai_status": "completed",
            "explanation": "Test explanation.",
            "impact": "Test impact.",
            "recommendation": "Test recommendation.",
        }

    monkeypatch.setattr(
        "ai.batch.analyze_finding",
        fake_analyze,
    )

    findings = [
        {
            "file": "first.py",
            "line": 10,
            "vulnerability": "SQL Injection",
            "severity": "High",
            "confidence": 90,
            "code": "query = user_input",
        },
        {
            "file": "second.py",
            "line": 20,
            "vulnerability": "XSS",
            "severity": "Medium",
            "confidence": 85,
            "code": "element.innerHTML = user_input",
        },
        {
            "file": "third.py",
            "line": 30,
            "vulnerability": "SSRF",
            "severity": "Low",
            "confidence": 80,
            "code": "requests.get(url)",
        },
    ]

    result = analyze_findings(findings)

    assert result["findings_count"] == 3
    assert result["successful_analyses"] == 3
    assert result["failed_analyses"] == 0

    returned = result["results"]
    assert [item["file"] for item in returned] == [
        "first.py",
        "second.py",
        "third.py",
    ]
    assert [item["vulnerability"] for item in returned] == [
        "SQL Injection",
        "XSS",
        "SSRF",
    ]
    assert all(item["ai_status"] == "completed" for item in returned)
