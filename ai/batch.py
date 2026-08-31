# ======================================================
# Multiple Finding Analysis
# ======================================================

from .input import VulnerabilityInput
from .llm import analyze_vulnerability


# ======================================================
# Analyze Multiple Findings
# ======================================================

def analyze_findings(findings):
    """
    Analyze multiple scanner findings.

    Each finding is processed independently using the
    existing single-finding analysis pipeline.

    Input:
        List of VulnerabilityInput objects

    Output:
        Dictionary containing individual results and
        aggregate information.
    """

    results = []

    for finding in findings:

        result = analyze_vulnerability(
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
        if result.get("ai_status") == "success"
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
            total_risk_score /
            total_findings,
            2
        )

    else:

        average_risk_score = 0


    # --------------------------------------------------
    # Return batch result
    # --------------------------------------------------

    return {
        "findings_count": total_findings,

        "successful_analyses": (
            successful_analyses
        ),

        "failed_analyses": (
            failed_analyses
        ),

        "average_risk_score": (
            average_risk_score
        ),

        "results": results
    }


# ======================================================
# Convenience Function
# ======================================================

def analyze_finding_dicts(findings):
    """
    Analyze findings supplied as dictionaries.

    Example:

        [
            {
                "file": "app.py",
                "line": 25,
                "vulnerability": "SQLi",
                "severity": "High",
                "confidence": 90,
                "code": "query = user_input"
            }
        ]
    """

    validated_findings = []

    for finding in findings:

        validated_finding = (
            VulnerabilityInput(
                **finding
            )
        )

        validated_findings.append(
            validated_finding
        )

    return analyze_findings(
        validated_findings
    )