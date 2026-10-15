
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

def test_batch_preserves_code_evidence_on_success_and_exception(monkeypatch):
    from ai.batch import analyze_findings

    def fake_analyze(finding):
        if finding["file"] == "broken.py":
            raise RuntimeError("Simulated analysis failure")

        return {
            "file": finding["file"],
            "line": finding["line"],
            "code": finding["code"],
            "vulnerability": finding["vulnerability"],
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "risk_score": 80.0,
            "risk_level": "Critical",
            "owasp": "A03:2021 Injection",
            "cwe": "CWE-89",
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
            "file": "safe-test.py",
            "line": 10,
            "vulnerability": "SQL Injection",
            "severity": "High",
            "confidence": 90,
            "code": "query = user_input",
        },
        {
            "file": "broken.py",
            "line": 20,
            "vulnerability": "XSS",
            "severity": "Medium",
            "confidence": 85,
            "code": "element.innerHTML = user_input",
        },
    ]

    result = analyze_findings(findings)
    returned = result["results"]

    assert len(returned) == 2

    # Successful analysis keeps its own scanner evidence.
    assert returned[0]["file"] == "safe-test.py"
    assert returned[0]["code"] == "query = user_input"
    assert returned[0]["cwe"] == "CWE-89"
    assert returned[0]["ai_status"] == "completed"

    # An exception must not stop the batch or lose scanner evidence.
    assert returned[1]["file"] == "broken.py"
    assert returned[1]["code"] == "element.innerHTML = user_input"
    assert returned[1]["line"] == 20
    assert returned[1]["vulnerability"] == "XSS"
    assert returned[1]["severity"] == "Medium"
    assert returned[1]["confidence"] == 85
    assert returned[1]["ai_status"] == "failed"

    assert result["findings_count"] == 2
    assert result["successful_analyses"] == 1
    assert result["failed_analyses"] == 1
