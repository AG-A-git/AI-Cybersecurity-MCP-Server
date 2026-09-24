# ======================================================
# Multiple Finding Analysis
# ======================================================

from .input import VulnerabilityInput
from .analysis import analyze_finding


# ======================================================
# Analyze Multiple Findings
# ======================================================

def analyze_findings(findings):
    """
    Analyze multiple scanner findings.

    Each finding can be either a dictionary or a
    VulnerabilityInput object.

    Output:
        Dictionary containing individual results
        and aggregate information.
    """

    results = []

    for finding in findings:

        if isinstance(finding, VulnerabilityInput):
            finding = finding.model_dump()

        result = analyze_finding(
            finding
        )

        results.append(
            result
        )

    # --------------------------------------------------
    # Calculate aggregate information
    # --------------------------------------------------

    total_findings = len(results)

    successful_analyses = sum(
        1
        for result in results
        if result.get("ai_status") == "completed"
    )

    failed_analyses = (
        total_findings -
        successful_analyses
    )

    total_risk_score = sum(
        result.get("risk_score", 0)
        for result in results
    )

    if total_findings > 0:
        average_risk_score = round(
            total_risk_score / total_findings,
            2
        )
    else:
        average_risk_score = 0

    return {
        "findings_count": total_findings,
        "successful_analyses": successful_analyses,
        "failed_analyses": failed_analyses,
        "average_risk_score": average_risk_score,
        "results": results
    }


# ======================================================
# Convenience Function
# ======================================================

def analyze_finding_dicts(findings):
    """
    Analyze findings supplied as dictionaries.
    """

    validated_findings = []

    for finding in findings:

        validated_finding = VulnerabilityInput(
            **finding
        )

        validated_findings.append(
            validated_finding
        )

    return analyze_findings(
        validated_findings
    )


# ======================================================
# Generate Security Report
# ======================================================

def generate_report(
    findings,
    project=None
):
    """
    Generate a complete security report.

    Input:
        findings:
            List of VulnerabilityInput objects or
            scanner finding dictionaries.

        project:
            Optional project name or project path.

    Output:
        Dictionary containing report metadata,
        aggregate statistics, and analyzed findings.
    """

    if not findings:
        return {
            "project": project,
            "total_findings": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "average_risk_score": 0,
            "findings": []
        }

    if isinstance(findings[0], dict):
        batch_result = analyze_finding_dicts(
            findings
        )
    else:
        batch_result = analyze_findings(
            findings
        )

    return {
        "project": project,
        "total_findings": batch_result["findings_count"],
        "successful_analyses": batch_result["successful_analyses"],
        "failed_analyses": batch_result["failed_analyses"],
        "average_risk_score": batch_result["average_risk_score"],
        "findings": batch_result["results"]
    }