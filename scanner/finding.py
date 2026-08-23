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
    """

    return {
        "file_name": str(file_name),
        "line_number": line_number,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "confidence": confidence,
        "code": code,
        "owasp": owasp,
        "cwe": cwe
    }