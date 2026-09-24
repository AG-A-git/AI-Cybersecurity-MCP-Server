"""
Utilities for formatting AI vulnerability analysis responses.
"""


def format_ai_response(analysis):
    """
    Return the standardized security analysis response.

    The risk score, risk level, OWASP mapping, and CWE mapping
    come from the centralized analysis pipeline.
    """

    return {
        "file": analysis["file"],
        "line": analysis["line"],
        "vulnerability": analysis["vulnerability"],
        "severity": analysis["severity"],
        "confidence": analysis["confidence"],
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "owasp": analysis["owasp"],
        "cwe": analysis["cwe"],
        "ai_status": analysis["ai_status"],
        "explanation": analysis["explanation"],
        "impact": analysis["impact"],
        "recommendation": analysis["recommendation"]
    }