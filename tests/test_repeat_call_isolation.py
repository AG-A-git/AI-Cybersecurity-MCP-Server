import json

from ai.analysis import analyze_finding
from ai.batch import analyze_findings as analyze_batch_findings
from ai.risk_score import calculate_risk


VALID_RESPONSE = json.dumps({
    "explanation": "Synthetic explanation for this finding.",
    "impact": "Synthetic impact for this finding.",
    "recommendation": "Use the appropriate secure coding fix.",
    "secure_practice": "Validate input and follow secure coding practices.",
})


class SequenceClient:
    """Deterministic fake AI client for repeated-call tests."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.call_count = 0

    def generate(self, prompt):
        self.call_count += 1

        if not self.outcomes:
            raise AssertionError("No mocked AI response remains.")

        outcome = self.outcomes.pop(0)

        if isinstance(outcome, BaseException):
            raise outcome

        return outcome


def make_finding(
    file,
    line,
    vulnerability,
    severity,
    confidence,
    code,
    finding_id=None,
):
    finding = {
        "file": file,
        "line": line,
        "vulnerability": vulnerability,
        "severity": severity,
        "confidence": confidence,
        "code": code,
    }

    if finding_id is not None:
        finding["finding_id"] = finding_id

    return finding


def analyze_in_order(findings):
    return [
        analyze_finding(
            finding,
            client=SequenceClient([VALID_RESPONSE]),
        )
        for finding in findings
    ]


def test_identical_repeated_calls_return_independent_results():
    finding = make_finding(
        "alpha.py", 11, "SQL Injection", "Critical", 95,
        "cursor.execute(query)",
    )
    client = SequenceClient([VALID_RESPONSE, VALID_RESPONSE])

    first = analyze_finding(finding, client=client)
    second = analyze_finding(finding, client=client)

    assert first == second
    assert first is not second
    assert client.call_count == 2

    # Mutating one returned result must not change the other.
    first["explanation"] = "Modified by the test."
    first["risk_score"] = -1

    assert second["explanation"] == (
        "Synthetic explanation for this finding."
    )
    assert second["risk_score"] == calculate_risk(
        "Critical", 95, "SQL Injection"
    )


def test_reverse_order_keeps_finding_metadata_and_risk_associated():
    alpha = make_finding(
        "alpha.py", 11, "SQL Injection", "Critical", 95,
        "cursor.execute(query)",
    )
    beta = make_finding(
        "beta.py", 24, "XSS", "Low", 70,
        "element.innerHTML = value",
    )

    forward = analyze_in_order([alpha, beta])
    reverse = analyze_in_order([beta, alpha])

    assert [item["file"] for item in forward] == [
        "alpha.py", "beta.py"
    ]
    assert [item["file"] for item in reverse] == [
        "beta.py", "alpha.py"
    ]

    expected = {
        "alpha.py": {
            "line": 11,
            "vulnerability": "SQL Injection",
            "code": "cursor.execute(query)",
            "risk_score": calculate_risk(
                "Critical", 95, "SQL Injection"
            ),
        },
        "beta.py": {
            "line": 24,
            "vulnerability": "XSS",
            "code": "element.innerHTML = value",
            "risk_score": calculate_risk("Low", 70, "XSS"),
        },
    }

    for result in forward + reverse:
        assert result["ai_status"] == "completed"
        for field, value in expected[result["file"]].items():
            assert result[field] == value


def test_failure_followed_by_success_does_not_return_stale_data():
    alpha = make_finding(
        "alpha.py", 11, "SQL Injection", "Critical", 95,
        "cursor.execute(query)",
    )
    beta = make_finding(
        "beta.py", 24, "XSS", "Low", 70,
        "element.innerHTML = value",
    )

    # RuntimeError is retried once by the existing implementation.
    client = SequenceClient([
        RuntimeError("Synthetic first-call failure"),
        RuntimeError("Synthetic retry failure"),
        VALID_RESPONSE,
    ])

    failed = analyze_finding(alpha, client=client)
    succeeded = analyze_finding(beta, client=client)

    assert failed["ai_status"] == "failed"
    assert failed["file"] == "alpha.py"
    assert failed["line"] == 11
    assert failed["explanation"] is None
    assert failed["impact"] is None

    assert succeeded["ai_status"] == "completed"
    assert succeeded["file"] == "beta.py"
    assert succeeded["line"] == 24
    assert succeeded["code"] == "element.innerHTML = value"
    assert succeeded["severity"] == "Low"
    assert succeeded["risk_score"] == calculate_risk(
        "Low", 70, "XSS"
    )
    assert succeeded["explanation"] == (
        "Synthetic explanation for this finding."
    )


def test_success_followed_by_failure_does_not_return_stale_data():
    alpha = make_finding(
        "alpha.py", 11, "SQL Injection", "Critical", 95,
        "cursor.execute(query)",
    )
    beta = make_finding(
        "beta.py", 24, "XSS", "Low", 70,
        "element.innerHTML = value",
    )

    client = SequenceClient([
        VALID_RESPONSE,
        RuntimeError("Synthetic second-call failure"),
        RuntimeError("Synthetic retry failure"),
    ])

    succeeded = analyze_finding(alpha, client=client)
    failed = analyze_finding(beta, client=client)

    assert succeeded["ai_status"] == "completed"
    assert succeeded["file"] == "alpha.py"
    assert succeeded["explanation"] == (
        "Synthetic explanation for this finding."
    )

    assert failed["ai_status"] == "failed"
    assert failed["file"] == "beta.py"
    assert failed["line"] == 24
    assert failed["code"] == "element.innerHTML = value"
    assert failed["severity"] == "Low"
    assert failed["risk_score"] == calculate_risk("Low", 70, "XSS")
    assert failed["explanation"] is None
    assert failed["impact"] is None
    assert failed["recommendation"] == (
        "AI analysis service unavailable."
    )


def test_mutating_input_later_does_not_change_previous_result():
    finding = make_finding(
        "original.py", 12, "SQL Injection", "Critical", 95,
        "original_query",
    )
    client = SequenceClient([VALID_RESPONSE, VALID_RESPONSE])

    first = analyze_finding(finding, client=client)

    finding["file"] = "changed.py"
    finding["line"] = 99
    finding["code"] = "changed_query"
    finding["severity"] = "Low"
    finding["confidence"] = 70

    second = analyze_finding(finding, client=client)

    assert first["file"] == "original.py"
    assert first["line"] == 12
    assert first["code"] == "original_query"
    assert first["severity"] == "Critical"
    assert first["confidence"] == 95
    assert first["risk_score"] == calculate_risk(
        "Critical", 95, "SQL Injection"
    )

    assert second["file"] == "changed.py"
    assert second["line"] == 99
    assert second["code"] == "changed_query"
    assert second["severity"] == "Low"
    assert second["confidence"] == 70
    assert second["risk_score"] == calculate_risk(
        "Low", 70, "SQL Injection"
    )


def test_batch_preserves_finding_ids_for_success_and_failure(monkeypatch):
    successful_finding = make_finding(
        "success.py", 10, "SQL Injection", "High", 90,
        "query = user_input",
        finding_id="finding-success",
    )
    failing_finding = make_finding(
        "failure.py", 20, "XSS", "InvalidSeverity", 85,
        "element.innerHTML = user_input",
        finding_id="finding-failure",
    )

    monkeypatch.setattr(
        "ai.analysis.OllamaClient",
        lambda: SequenceClient([VALID_RESPONSE]),
    )

    batch = analyze_batch_findings([
        successful_finding,
        failing_finding,
    ])

    assert batch["findings_count"] == 2
    assert batch["successful_analyses"] == 1
    assert batch["failed_analyses"] == 1

    results = batch["results"]
    assert results[0]["file"] == "success.py"
    assert results[0]["ai_status"] == "completed"
    assert results[1]["file"] == "failure.py"
    assert results[1]["ai_status"] == "failed"

    # Both outcomes should remain associated with their input IDs.
    assert [item.get("finding_id") for item in results] == [
        "finding-success",
        "finding-failure",
    ]
