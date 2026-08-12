SEVERITY_SCORE = {
    "Critical": 95,
    "High": 80,
    "Medium": 55,
    "Low": 25
}


def calculate_risk(severity, confidence=100, vulnerability=None):
    """
    Calculate a deterministic risk score using
    severity and scanner confidence.
    """

    severity = severity.strip().capitalize()

    # Keep confidence between 0 and 100
    confidence = max(
        0,
        min(float(confidence), 100)
    )

    # Get base score from severity
    severity_score = SEVERITY_SCORE.get(
        severity,
        0
    )

    # Combine severity and confidence
    risk_score = (
        severity_score
        * (confidence / 100)
    )

    return round(risk_score, 2)


def classify_risk(score):

    if score >= 90:
        return "Critical"

    elif score >= 70:
        return "High"

    elif score >= 40:
        return "Medium"

    elif score >= 10:
        return "Low"

    return "Unknown"


if __name__ == "__main__":

    test_cases = [
        ("Critical", 95),
        ("High", 90),
        ("Medium", 60),
        ("Low", 30)
    ]

    for severity, confidence in test_cases:

        risk = calculate_risk(
            severity,
            confidence
        )

        print(
            f"{severity} + {confidence}% "
            f"→ Risk Score: {risk} "
            f"→ {classify_risk(risk)}"
        )