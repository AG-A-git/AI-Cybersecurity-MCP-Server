
import json
import requests

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
        "file",
        "line",
        "code",
        "vulnerability",
        "severity",
        "confidence",
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


def test_timeout_retries_once_then_succeeds():
    class RetryClient:
        def __init__(self):
            self.calls = 0

        def generate(self, prompt):
            self.calls += 1

            if self.calls == 1:
                raise requests.exceptions.Timeout()

            return make_ai_response()

    client = RetryClient()
    result = analyze_finding(make_finding(), client=client)

    assert client.calls == 2
    assert result["ai_status"] == "completed"


def test_repeated_timeout_fails_after_one_retry():
    class TimeoutClient:
        def __init__(self):
            self.calls = 0

        def generate(self, prompt):
            self.calls += 1
            raise requests.exceptions.Timeout()

    client = TimeoutClient()
    result = analyze_finding(make_finding(), client=client)

    assert client.calls == 2
    assert result["ai_status"] == "failed"
    assert result["recommendation"] == (
        "AI analysis service unavailable."
    )
    assert result["file"] == "app.py"
    assert result["line"] == 10


def test_connection_error_retries_once_then_succeeds():
    class ConnectionErrorClient:
        def __init__(self):
            self.calls = 0

        def generate(self, prompt):
            self.calls += 1

            if self.calls == 1:
                raise requests.exceptions.ConnectionError(
                    "Ollama is temporarily unavailable"
                )

            return make_ai_response()

    client = ConnectionErrorClient()
    result = analyze_finding(make_finding(), client=client)

    assert client.calls == 2
    assert result["ai_status"] == "completed"


def test_repeated_connection_error_fails_after_one_retry():
    class ConnectionErrorClient:
        def __init__(self):
            self.calls = 0

        def generate(self, prompt):
            self.calls += 1
            raise requests.exceptions.ConnectionError(
                "Ollama is unavailable"
            )

    client = ConnectionErrorClient()
    result = analyze_finding(make_finding(), client=client)

    assert client.calls == 2
    assert result["ai_status"] == "failed"
    assert result["recommendation"] == (
        "AI analysis service unavailable."
    )
    assert result["file"] == "app.py"
    assert result["line"] == 10

def test_repeated_analyses_do_not_leak_state():
    first_finding = make_finding()
    first_finding["file"] = "first.py"
    first_finding["severity"] = "Critical"
    first_finding["confidence"] = 95

    second_finding = make_finding()
    second_finding["file"] = "second.py"
    second_finding["severity"] = "Low"
    second_finding["confidence"] = 40
    second_finding["vulnerability"] = "XSS"
    second_finding["code"] = "render(user_input)"

    first_result = analyze_finding(
        first_finding,
        client=FakeAIClient(
            make_ai_response(
                explanation="First finding explanation.",
                recommendation="First finding recommendation.",
            )
        ),
    )

    second_result = analyze_finding(
        second_finding,
        client=FakeAIClient(
            make_ai_response(
                explanation="Second finding explanation.",
                recommendation="Second finding recommendation.",
            )
        ),
    )

    assert first_result["ai_status"] == "completed"
    assert second_result["ai_status"] == "completed"

    assert first_result["file"] == "first.py"
    assert first_result["severity"] == "Critical"
    assert first_result["explanation"] == "First finding explanation."
    assert first_result["recommendation"] == "First finding recommendation."

    assert second_result["file"] == "second.py"
    assert second_result["severity"] == "Low"
    assert second_result["vulnerability"] == "XSS"
    assert second_result["explanation"] == "Second finding explanation."
    assert second_result["recommendation"] == "Second finding recommendation."

    assert first_result["explanation"] != second_result["explanation"]
    assert first_result["risk_score"] != second_result["risk_score"]

def test_http_4xx_error_fails_without_retry():
    class HttpErrorClient:
        def __init__(self):
            self.calls = 0

        def generate(self, prompt):
            self.calls += 1
            response = requests.Response()
            response.status_code = 401
            raise requests.exceptions.HTTPError(
                "401 Unauthorized",
                response=response,
            )

    client = HttpErrorClient()
    result = analyze_finding(make_finding(), client=client)

    assert client.calls == 1
    assert result["ai_status"] == "failed"
    assert result["recommendation"] == (
        "AI analysis service unavailable."
    )
    assert result["file"] == "app.py"
    assert result["line"] == 10
