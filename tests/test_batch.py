
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
