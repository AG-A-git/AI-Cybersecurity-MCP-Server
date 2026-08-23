# ======================================================
# Initial Risk Scoring Model
# ======================================================

SEVERITY_WEIGHTS = {
    "Critical": 90,
    "High": 75,
    "Medium": 50,
    "Low": 25
}


# ======================================================
# Calculate Risk Score
# ======================================================

def calculate_risk(severity, confidence):
    """
    Calculate an initial deterministic risk score.

    Severity provides the base score.
    Confidence adjusts the score based on scanner confidence.

    This is an initial project model and will be refined later.
    """

    # Normalize severity
    normalized_severity = severity.strip().capitalize()

    # Get severity weight
    base_score = SEVERITY_WEIGHTS.get(
        normalized_severity,
        0
    )

    # Normalize confidence
    confidence = float(confidence)

    # Make sure confidence stays within 0–100
    confidence = max(
        0,
        min(confidence, 100)
    )

    # Adjust severity score using confidence
    risk_score = base_score * (confidence / 100)

    # Keep score within 0–100
    risk_score = max(
        0,
        min(risk_score, 100)
    )

    return round(
        risk_score,
        2
    )


# ======================================================
# Classify Risk
# ======================================================

def classify_risk(risk_score):
    """
    Convert numeric risk score into a risk level.
    """

    if risk_score >= 90:
        return "Critical"

    elif risk_score >= 75:
        return "High"

    elif risk_score >= 50:
        return "Medium"

    elif risk_score >= 25:
        return "Low"

    else:
        return "Informational"