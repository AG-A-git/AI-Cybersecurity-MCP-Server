
import json

import pytest

from ai.analysis import analyze_finding


def make_finding(code):
    return {
        "file": "example.py",
        "line": 10,
        "vulnerability": "SQL Injection",
        "severity": "High",
        "confidence": 60.0,
        "code": code,
    }


def make_ai_response(
    explanation=(
        "The available evidence is insufficient to confirm exploitability."
    ),
    impact=(
        "The impact cannot be verified from the supplied evidence alone."
    ),
    recommendation=(
        "Review the query construction and data flow before selecting a fix."
    ),
    secure_practice=(
        "Use parameterized queries when incorporating untrusted values into SQL."
    ),
):
    return json.dumps(
        {
            "explanation": explanation,
            "impact": impact,
            "recommendation": recommendation,
            "secure_practice": secure_practice,
        }
    )


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        return self.response


@pytest.mark.parametrize("code", ["", "   ", "\t\n"])
def test_empty_or_whitespace_code_does_not_crash(code):
    finding = make_finding(code)
    client = FakeClient(make_ai_response())

    try:
        result = analyze_finding(finding, client=client)
    except Exception:
        # Rejecting invalid input is acceptable.
        return

    assert result["file"] == "example.py"
    assert result["line"] == 10
    assert result["severity"] == "High"


def test_missing_code_evidence_does_not_crash():
    finding = make_finding("")
    finding.pop("code")
    client = FakeClient(make_ai_response())

    try:
        result = analyze_finding(finding, client=client)
    except Exception:
        # Rejecting a missing required field is acceptable.
        return

    assert result["file"] == "example.py"
    assert result["line"] == 10
    assert result["severity"] == "High"


def test_inconclusive_evidence_can_be_reported_with_uncertainty():
    finding = make_finding("query = build_query()")
    client = FakeClient(make_ai_response())

    result = analyze_finding(finding, client=client)

    assert result["ai_status"] == "completed"
    assert result["file"] == finding["file"]
    assert result["line"] == finding["line"]
    assert result["code"] == finding["code"]
    assert "insufficient" in result["explanation"].lower()


def test_ai_claim_of_unprovided_code_location_is_detected():
    finding = make_finding("query = build_query()")
    client = FakeClient(
        make_ai_response(
            explanation="The vulnerable call is at database.py:88."
        )
    )

    result = analyze_finding(finding, client=client)

    assert result["file"] == "example.py"
    assert result["line"] == 10
    assert "database.py:88" not in result["explanation"]


def test_unsupported_remediation_claim_is_detected():
    finding = make_finding("query = build_query()")
    client = FakeClient(
        make_ai_response(
            recommendation="Replace the unsafe call at database.py:88."
        )
    )

    result = analyze_finding(finding, client=client)

    assert result["file"] == finding["file"]
    assert result["line"] == finding["line"]
    assert result["code"] == finding["code"]
    assert result["severity"] == finding["severity"]
    assert "database.py:88" not in result["recommendation"]


def test_scanner_metadata_is_preserved_with_ai_recommendation():
    finding = make_finding("query = build_query()")
    client = FakeClient(
        make_ai_response(
            recommendation="Review the query and use parameterized SQL."
        )
    )

    result = analyze_finding(finding, client=client)

    assert result["file"] == finding["file"]
    assert result["line"] == finding["line"]
    assert result["code"] == finding["code"]
    assert result["severity"] == finding["severity"]
