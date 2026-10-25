
import hashlib
import math


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


# Must match the severity labels accepted by the existing
# standardized finding contract and tests.
VALID_SEVERITIES = {
    "Critical",
    "High",
    "Medium",
    "Low",
}


def create_finding_fingerprint(
    file_name,
    line_number,
    vulnerability_type,
    code,
):
    """Create a deterministic fingerprint for a vulnerability finding."""

    identity = "|".join(
        [
            str(file_name),
            str(line_number),
            str(vulnerability_type),
            str(code),
        ]
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


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

    Confidence uses the scanner's 0-100 scale.
    Evidence and fingerprint are optional metadata.
    """

    # --------------------------------------------------------
    # Validate finding structure
    # --------------------------------------------------------

    if not isinstance(finding, dict):
        raise ValueError("finding must be a dictionary")

    missing = REQUIRED_FIELDS - finding.keys()

    if missing:
        raise ValueError(
            f"Finding missing fields: {missing}"
        )

    # --------------------------------------------------------
    # Validate file name
    # --------------------------------------------------------

    if not isinstance(finding["file_name"], str):
        raise ValueError("file_name must be a string")

    if not finding["file_name"].strip():
        raise ValueError("file_name must not be empty")

    # --------------------------------------------------------
    # Validate line number
    # --------------------------------------------------------

    line_number = finding["line_number"]

    # bool is a subclass of int in Python, so reject it explicitly.
    if (
        not isinstance(line_number, int)
        or isinstance(line_number, bool)
    ):
        raise ValueError("line_number must be an integer")

    if line_number < 1:
        raise ValueError("line_number must be greater than 0")

    # --------------------------------------------------------
    # Validate vulnerability type
    # --------------------------------------------------------

    vulnerability_type = finding["vulnerability_type"]

    if not isinstance(vulnerability_type, str):
        raise ValueError(
            "vulnerability_type must be a string"
        )

    if not vulnerability_type.strip():
        raise ValueError(
            "vulnerability_type must not be empty"
        )

    # --------------------------------------------------------
    # Validate severity
    # --------------------------------------------------------

    severity = finding["severity"]

    if (
        not isinstance(severity, str)
        or severity not in VALID_SEVERITIES
    ):
        raise ValueError(
            f"Invalid severity: {severity}"
        )

    # --------------------------------------------------------
    # Validate confidence
    # --------------------------------------------------------

    confidence = finding["confidence"]

    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
    ):
        raise ValueError("confidence must be numeric")

    if not math.isfinite(confidence):
        raise ValueError(
            "confidence must be a finite number"
        )

    if not 0 <= confidence <= 100:
        raise ValueError(
            "confidence must be between 0 and 100"
        )

    # --------------------------------------------------------
    # Validate code
    # --------------------------------------------------------

    if not isinstance(finding["code"], str):
        raise ValueError("code must be a string")

    # --------------------------------------------------------
    # Validate optional evidence
    # --------------------------------------------------------

    if "evidence" in finding:
        if not isinstance(finding["evidence"], dict):
            raise ValueError(
                "evidence must be a dictionary"
            )

    # --------------------------------------------------------
    # Validate optional fingerprint
    # --------------------------------------------------------

    if "fingerprint" in finding:
        if not isinstance(finding["fingerprint"], str):
            raise ValueError(
                "fingerprint must be a string"
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
    cwe,
    evidence=None,
):
    """
    Create and validate a standardized vulnerability finding.

    All scanner rules should use this helper to maintain
    consistent output structure.

    Evidence is optional and can describe source-to-sink
    relationships when supported by the scanner.
    """

    finding = {
        "file_name": str(file_name),
        "line_number": line_number,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "confidence": confidence,
        "code": code,
        "owasp": owasp,
        "cwe": cwe,
        "fingerprint": create_finding_fingerprint(
            file_name,
            line_number,
            vulnerability_type,
            code,
        ),
    }

    if evidence is not None:
        finding["evidence"] = evidence

    return validate_finding(finding)
