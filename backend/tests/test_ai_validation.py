import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ai.input import validate_vulnerability
from ai.response import parse_ai_response


VALID_FINDING = {
    "file": "app.py",
    "line": 12,
    "vulnerability": "SQL Injection",
    "severity": "High",
    "confidence": 90,
    "code": "cursor.execute(query)",
}


def test_valid_vulnerability_input_is_accepted():
    finding = validate_vulnerability(VALID_FINDING)

    assert finding.file == "app.py"
    assert finding.line == 12
    assert finding.confidence == 90


@pytest.mark.parametrize("confidence", [-1, 101, float("nan")])
def test_invalid_confidence_is_rejected(confidence):
    with pytest.raises(ValidationError):
        validate_vulnerability({
            **VALID_FINDING,
            "confidence": confidence,
        })


@pytest.mark.parametrize(
    "response",
    [
        "",
        "not JSON",
        "[]",
        "null",
        '{"explanation": "incomplete"',
    ],
)
def test_invalid_ai_responses_are_rejected(response):
    with pytest.raises(ValueError):
        parse_ai_response(response)


def test_valid_ai_json_is_parsed():
    result = parse_ai_response(
        '{"explanation":"Reason","impact":"Impact",'
        '"recommendation":"Fix it",'
        '"secure_practice":"Use parameterized queries"}'
    )

    assert result.explanation == "Reason"
    assert result.impact == "Impact"
    assert result.recommendation == "Fix it"
    assert result.secure_practice == "Use parameterized queries"


def test_missing_required_ai_field_is_rejected():
    with pytest.raises(ValueError, match="missing or has invalid fields"):
        parse_ai_response(
            '{"explanation":"Reason","impact":"Impact",'
            '"recommendation":"Fix it"}'
        )
