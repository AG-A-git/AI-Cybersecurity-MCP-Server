from unittest.mock import patch

from ai.batch import analyze_findings


def test_analyze_findings_continues_after_one_failure():
    findings = [
        {
            "file": "first.py",
            "line": 10,
            "vulnerability": "SQL Injection",
            "severity": "Critical",
            "confidence": 95,
            "code": "cursor.execute(query)",
        },
        {
            "file": "second.py",
            "line": 20,
            "vulnerability": "Cross-Site Scripting",
            "severity": "High",
            "confidence": 90,
            "code": "render(user_input)",
        },
    ]

    successful_result = {
        "file": "second.py",
        "line": 20,
        "vulnerability": "Cross-Site Scripting",
        "severity": "High",
        "confidence": 90,
        "risk_score": 80,
        "ai_status": "completed",
        "explanation": "Mocked successful analysis",
        "impact": "Mocked impact",
        "recommendation": "Apply appropriate output encoding.",
    }

    with patch(
        "ai.batch.analyze_finding",
        side_effect=[
            RuntimeError("Simulated AI failure"),
            successful_result,
        ],
    ) as mock_analyze:
        result = analyze_findings(findings)

    assert mock_analyze.call_count == 2
    assert result["findings_count"] == 2
    assert result["failed_analyses"] == 1
    assert result["successful_analyses"] == 1

    failed = result["results"][0]
    assert failed["ai_status"] == "failed"
    assert failed["severity"] == "Critical"
    assert failed["confidence"] == 95

    successful = result["results"][1]
    assert successful["ai_status"] == "completed"
    assert successful["severity"] == "High"
    assert successful["confidence"] == 90
