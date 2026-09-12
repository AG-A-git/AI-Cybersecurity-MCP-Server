# ============================================================
# Standard Finding Validation
# ============================================================

REQUIRED_FIELDS = {
    "file_name",
    "line_number",
    "vulnerability_type",
    "severity",
    "confidence",
    "code",
}


VALID_SEVERITIES = {
    "Critical",
    "High",
    "Medium",
    "Low",
}


def validate_finding(finding):
    """
    Validate a standardized vulnerability finding.

    Required fields:
        file_name
        line_number
        vulnerability_type
        severity
        confidence
        code
    """

    # --------------------------------------------------------
    # Check required fields
    # --------------------------------------------------------

    missing = REQUIRED_FIELDS - finding.keys()

    if missing:
        raise ValueError(
            f"Finding missing fields: {missing}"
        )

    # --------------------------------------------------------
    # Check line number
    # --------------------------------------------------------

    if not isinstance(
        finding["line_number"],
        int
    ):
        raise ValueError(
            "line_number must be an integer"
        )

    if finding["line_number"] < 1:
        raise ValueError(
            "line_number must be greater than 0"
        )

    # --------------------------------------------------------
    # Check confidence
    # --------------------------------------------------------

    if not isinstance(
        finding["confidence"],
        (int, float)
    ):
        raise ValueError(
            "confidence must be numeric"
        )

    if not 0 <= finding["confidence"] <= 100:
        raise ValueError(
            "confidence must be between 0 and 100"
        )

    # --------------------------------------------------------
    # Check severity
    # --------------------------------------------------------

    if finding["severity"] not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity: {finding['severity']}"
        )

    return finding


# ============================================================
# Create Standardized Finding
# ============================================================

def create_finding(
    file_name,
    line_number,
    vulnerability_type,
    severity,
    confidence,
    code,
    owasp,
    cwe
):
    """
    Create a standardized vulnerability finding.

    All scanner rules should use this helper so that
    vulnerability output remains consistent.
    """

    finding = {
        "file_name": str(file_name),
        "line_number": line_number,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "confidence": confidence,
        "code": code,
        "owasp": owasp,
        "cwe": cwe
    }

    # Validate before returning the finding.
    return validate_finding(finding)