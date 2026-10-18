
import math

# ======================================================
# Deterministic Risk Scoring Model
# ======================================================

SEVERITY_WEIGHTS = {
    "Critical": 90,
    "High": 75,
    "Medium": 50,
    "Low": 25,
}


# ======================================================
# Vulnerability Impact Factors
# ======================================================

VULNERABILITY_IMPACT_FACTORS = {
    "SQL Injection": 1.15,
    "XSS": 1.05,
    "Command Injection": 1.15,
    "LDAP Injection": 1.10,
    "Hardcoded Credentials/Secrets": 1.15,
    "Weak Cryptography": 1.05,
    "Broken Access Control": 1.15,
    "Security Misconfiguration": 1.00,
    "Insecure Authentication": 1.10,
    "Insecure Deserialization": 1.15,
    "Sensitive Data Exposure": 1.10,
    "SSRF": 1.15,
}


# ======================================================
# Normalize Severity
# ======================================================

def normalize_severity(severity):
    """
    Normalize a severity value.

    Examples:
        "high"   -> "High"
        " HIGH " -> "High"
    """

    if not isinstance(severity, str):
        raise ValueError("Severity must be a string.")

    normalized_severity = severity.strip().capitalize()

    if normalized_severity not in SEVERITY_WEIGHTS:
        raise ValueError(f"Invalid severity: {severity}")

    return normalized_severity


# ======================================================
# Validate Confidence
# ======================================================

def validate_confidence(confidence):
    """
    Validate scanner confidence.

    Confidence must be finite and between 0 and 100.
    """

    try:
        confidence = float(confidence)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Confidence must be a number.") from exc

    if (
        not math.isfinite(confidence)
        or confidence < 0
        or confidence > 100
    ):
        raise ValueError(
            "Confidence must be a finite number between 0 and 100."
        )

    return confidence


# ======================================================
# Get Vulnerability Impact Factor
# ======================================================

def get_vulnerability_impact(vulnerability_type):
    """
    Return the impact factor for a canonical vulnerability type.

    Unknown vulnerability types use 1.00.
    """

    if not vulnerability_type:
        return 1.00

    return VULNERABILITY_IMPACT_FACTORS.get(
        vulnerability_type,
        1.00,
    )


# ======================================================
# Calculate Risk Score
# ======================================================

def calculate_risk(
    severity,
    confidence,
    vulnerability_type=None,
):
    """
    Calculate the deterministic risk score.

    Formula:
        Base Severity Score
        * Confidence Factor
        * Vulnerability Impact Factor

    The final score is bounded between 0 and 100
    and rounded to two decimal places.
    """

    # Normalize and validate severity.
    normalized_severity = normalize_severity(severity)

    base_score = SEVERITY_WEIGHTS[normalized_severity]

    # Validate confidence.
    confidence = validate_confidence(confidence)

    # Calculate confidence factor.
    confidence_factor = confidence / 100

    # Get vulnerability impact factor.
    impact_factor = get_vulnerability_impact(vulnerability_type)

    # Calculate risk.
    risk_score = (
        base_score
        * confidence_factor
        * impact_factor
    )

    # Keep score between 0 and 100.
    risk_score = max(0, min(risk_score, 100))

    return round(risk_score, 2)


# ======================================================
# Classify Risk
# ======================================================

def classify_risk(risk_score):
    """
    Convert a finite numeric risk score into a risk level.
    """

    try:
        risk_score = float(risk_score)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Risk score must be numeric.") from exc

    if (
        not math.isfinite(risk_score)
        or risk_score < 0
        or risk_score > 100
    ):
        raise ValueError(
            "Risk score must be a finite number between 0 and 100."
        )

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
