"""
Utilities for formatting AI vulnerability analysis responses.
"""


def format_ai_response(
    severity,
    risk_score,
    owasp,
    cwe,
    explanation,
    recommendation
):
    """
    Return a standardized AI vulnerability response.
    """

    return {
        "severity": severity,
        "risk_score": risk_score,
        "owasp": owasp,
        "cwe": cwe,
        "explanation": explanation,
        "recommendation": recommendation
    }