
import pytest

from ai.risk_score import (
    calculate_risk,
    classify_risk,
    normalize_severity,
    validate_confidence,
)


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("Critical", "Critical"),
        ("HIGH", "High"),
        (" medium ", "Medium"),
        ("low", "Low"),
    ],
)
def test_normalize_valid_severity(severity, expected):
    assert normalize_severity(severity) == expected


@pytest.mark.parametrize(
    "severity",
    ["", "Very Dangerous", "Informational", None, 123],
)
def test_reject_invalid_severity(severity):
    with pytest.raises(ValueError):
        normalize_severity(severity)


@pytest.mark.parametrize("confidence", [0, 50, 100, 75.5, "90"])
def test_accept_valid_confidence(confidence):
    result = validate_confidence(confidence)
    assert 0 <= result <= 100


@pytest.mark.parametrize("confidence", [-1, 101, "invalid", None])
def test_reject_invalid_confidence(confidence):
    with pytest.raises(ValueError):
        validate_confidence(confidence)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "Informational"),
        (24.99, "Informational"),
        (25, "Low"),
        (49.99, "Low"),
        (50, "Medium"),
        (74.99, "Medium"),
        (75, "High"),
        (89.99, "High"),
        (90, "Critical"),
        (100, "Critical"),
    ],
)
def test_risk_classification_boundaries(score, expected):
    assert classify_risk(score) == expected


@pytest.mark.parametrize("score", [-1, 101, "invalid", None])
def test_reject_invalid_risk_score(score):
    with pytest.raises(ValueError):
        classify_risk(score)


def test_calculate_risk_uses_severity_confidence_and_vulnerability():
    # High = 75; confidence = 90%; SQL Injection factor = 1.15.
    assert calculate_risk("High", 90, "SQL Injection") == 77.62


def test_unknown_vulnerability_uses_default_impact_factor():
    # Unknown vulnerability types use the default impact factor of 1.00.
    assert calculate_risk("High", 100, "Unknown Vulnerability") == 75.0


def test_zero_confidence_produces_zero_risk():
    assert calculate_risk("Critical", 0, "SQL Injection") == 0.0
