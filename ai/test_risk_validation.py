import pytest

from ai.risk_score import (
    calculate_risk,
    classify_risk,
    normalize_severity,
    validate_confidence,
)


def test_valid_severity():
    assert normalize_severity("high") == "High"
    assert normalize_severity(" HIGH ") == "High"


def test_invalid_severity():
    with pytest.raises(ValueError):
        normalize_severity("Very Dangerous")


def test_valid_confidence():
    assert validate_confidence(0) == 0
    assert validate_confidence(50) == 50
    assert validate_confidence(100) == 100


def test_confidence_above_100():
    with pytest.raises(ValueError):
        validate_confidence(150)


def test_confidence_below_0():
    with pytest.raises(ValueError):
        validate_confidence(-1)


def test_invalid_confidence_text():
    with pytest.raises(ValueError):
        validate_confidence("unknown")


def test_risk_score_is_bounded():
    score = calculate_risk(
        "Critical",
        100,
        "SQL Injection",
    )

    assert 0 <= score <= 100


def test_risk_score_is_deterministic():
    score1 = calculate_risk(
        "High",
        90,
        "SQL Injection",
    )

    score2 = calculate_risk(
        "High",
        90,
        "SQL Injection",
    )

    assert score1 == score2


def test_risk_level_boundaries():
    assert classify_risk(0) == "Informational"
    assert classify_risk(24) == "Informational"
    assert classify_risk(25) == "Low"
    assert classify_risk(49) == "Low"
    assert classify_risk(50) == "Medium"
    assert classify_risk(74) == "Medium"
    assert classify_risk(75) == "High"
    assert classify_risk(89) == "High"
    assert classify_risk(90) == "Critical"
    assert classify_risk(100) == "Critical"


def test_invalid_risk_score():
    with pytest.raises(ValueError):
        classify_risk(101)

    with pytest.raises(ValueError):
        classify_risk(-1)