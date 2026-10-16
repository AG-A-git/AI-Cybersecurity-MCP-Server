import json

from ai.analysis import analyze_finding
from ai.mapping import get_mapping
from ai.risk_score import calculate_risk, classify_risk


class FakeAIClient:
    def __init__(self, response):
        self.response = response

    def generate(self, prompt):
        return self.response


def make_finding():
    return {
        "file": "app.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 90,
        "code": "cursor.execute(query)",
    }


def make_ai_response(**overrides):
    response = {
        "explanation": "User input may reach a database query.",
        "impact": "Unauthorized data access may be possible.",
        "recommendation": "Use parameterized SQL queries.",
        "secure_practice": "Separate SQL commands from user data.",
    }
    response.update(overrides)
    return json.dumps(response)


def test_analysis_preserves_scanner_metadata():
    finding = make_finding()
    result = analyze_finding(
        finding,
        client=FakeAIClient(make_ai_response()),
    )

    mapping = get_mapping(finding["vulnerability"])
    expected_score = calculate_risk(
        finding["severity"],
        finding["confidence"],
        finding["vulnerability"],
    )

    assert result["ai_status"] == "completed"
    for field in (
        "file", "line", "code", "vulnerability",
        "severity", "confidence",
    ):
        assert result[field] == finding[field]

    assert result["risk_score"] == expected_score
    assert result["risk_level"] == classify_risk(expected_score)
    assert result["owasp"] == mapping["owasp"]
    assert result["cwe"] == mapping["cwe"]


def test_ai_cannot_override_authoritative_metadata():
    finding = make_finding()
    response = make_ai_response(
        severity="Low",
        file="other.py",
        line=999,
        risk_score=0,
        risk_level="Low",
        owasp="AI-invented OWASP",
        cwe="AI-invented CWE",
    )

    result = analyze_finding(
        finding,
        client=FakeAIClient(response),
    )

    mapping = get_mapping(finding["vulnerability"])
    expected_score = calculate_risk(
        finding["severity"],
        finding["confidence"],
        finding["vulnerability"],
    )

    assert result["ai_status"] == "completed"
    assert result["file"] == finding["file"]
    assert result["line"] == finding["line"]
    assert result["severity"] == finding["severity"]
    assert result["risk_score"] == expected_score
    assert result["risk_level"] == classify_risk(expected_score)
    assert result["owasp"] == mapping["owasp"]
    assert result["cwe"] == mapping["cwe"]


def test_malformed_ai_response_preserves_finding_metadata():
    finding = make_finding()
    result = analyze_finding(
        finding,
        client=FakeAIClient("this is not JSON"),
    )

    assert result["ai_status"] == "failed"
    assert result["file"] == finding["file"]
    assert result["line"] == finding["line"]
    assert result["code"] == finding["code"]
    assert result["vulnerability"] == finding["vulnerability"]
    assert result["severity"] == finding["severity"]
    assert result["recommendation"] == (
        "AI analysis response was invalid."
    )
    assert result["explanation"] is None
    assert result["impact"] is None
