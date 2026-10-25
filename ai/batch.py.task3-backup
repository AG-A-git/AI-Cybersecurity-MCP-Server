from .analysis import analyze_finding


# ======================================================
# Analyze Multiple Findings
# ======================================================

def analyze_findings(findings):
    """
    Analyze multiple scanner findings independently.

    If one finding fails, the remaining findings
    continue to be analyzed.
    """

    results = []

    for finding in findings:

        try:
            result = analyze_finding(
                finding
            )

            results.append(
                result
            )

        except Exception as exc:

            # Keep the original scanner information.
            # One failed finding must not stop the batch.
            results.append(
                {
                    "finding_id": finding.get("finding_id"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "vulnerability": finding.get("vulnerability"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "ai_status": "failed",
                    "ai_error": str(exc),
                    "explanation": None,
                    "impact": None,
                    "recommendation": (
                        "AI analysis failed for this finding."
                    )
                }
            )

    # --------------------------------------------------
    # Calculate batch statistics
    # --------------------------------------------------

    total_findings = len(results)

    successful_results = [
        result
        for result in results
        if result.get("ai_status") == "completed"
    ]

    failed_results = [
        result
        for result in results
        if result.get("ai_status") == "failed"
    ]

    total_risk_score = sum(
        result.get("risk_score", 0) or 0
        for result in successful_results
    )

    average_risk_score = (
        total_risk_score / len(successful_results)
        if successful_results
        else 0
    )

    return {
        "findings_count": total_findings,
        "successful_analyses": len(successful_results),
        "failed_analyses": len(failed_results),
        "total_risk_score": total_risk_score,
        "average_risk_score": average_risk_score,
        "results": results
    }


# ======================================================
# Analyze Dictionary Findings
# ======================================================

def analyze_finding_dicts(findings):
    """
    Analyze findings supplied as dictionaries.
    """

    validated_findings = []

    for finding in findings:

        validated_findings.append(
            {
                "finding_id": finding.get("finding_id"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "vulnerability": finding.get("vulnerability"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "code": finding.get("code")
            }
        )

    return analyze_findings(
        validated_findings
    )


# ======================================================
# Generate Report
# ======================================================

def generate_report(
    findings,
    project=None
):
    """
    Generate an AI analysis report for multiple findings.
    """

    if not findings:

        return {
            "project": project,
            "total_findings": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "total_risk_score": 0,
            "average_risk_score": 0,
            "findings": []
        }

    if isinstance(
        findings[0],
        dict
    ):

        batch_result = analyze_finding_dicts(
            findings
        )

    else:

        batch_result = analyze_findings(
            findings
        )

    return {
        "project": project,
        "total_findings": batch_result[
            "findings_count"
        ],
        "successful_analyses": batch_result[
            "successful_analyses"
        ],
        "failed_analyses": batch_result[
            "failed_analyses"
        ],
        "total_risk_score": batch_result[
            "total_risk_score"
        ],
        "average_risk_score": batch_result[
            "average_risk_score"
        ],
        "findings": batch_result[
            "results"
        ]
    }