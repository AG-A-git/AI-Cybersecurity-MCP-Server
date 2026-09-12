from .batch import analyze_finding_dicts


def test_multiple_findings():
    findings = [
        {
            "file": "app.py",
            "line": 25,
            "vulnerability": "SQL Injection",
            "severity": "High",
            "confidence": 90,
            "code": "query = user_input",
        },
        {
            "file": "page.html",
            "line": 42,
            "vulnerability": "XSS",
            "severity": "Medium",
            "confidence": 85,
            "code": "innerHTML = user_input",
        },
        {
            "file": "config.py",
            "line": 10,
            "vulnerability": "Hardcoded Credentials/Secrets",
            "severity": "High",
            "confidence": 95,
            "code": "password = 'secret'",
        },
    ]

    result = analyze_finding_dicts(findings)

    assert result["findings_count"] == 3
    assert len(result["results"]) == 3