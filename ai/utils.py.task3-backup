"""
Utilities for formatting AI vulnerability analysis responses.
"""


def format_ai_response(analysis=None, **kwargs):
    """
    Return a standardized security analysis response.

    Supports either a dictionary or keyword arguments.
    """

    if analysis is None:
        analysis = kwargs
    elif kwargs:
        analysis = {**analysis, **kwargs}

    if not isinstance(analysis, dict):
        raise TypeError("analysis must be a dictionary or keyword arguments")

    return {
        "file": analysis.get("file"),
        "line": analysis.get("line"),
        "vulnerability": analysis.get("vulnerability"),
        "severity": analysis.get("severity"),
        "confidence": analysis.get("confidence"),
        "risk_score": analysis.get("risk_score"),
        "risk_level": analysis.get("risk_level"),
        "owasp": analysis.get("owasp"),
        "cwe": analysis.get("cwe"),
        "ai_status": analysis.get("ai_status"),
        "explanation": analysis.get("explanation"),
        "impact": analysis.get("impact"),
        "recommendation": analysis.get("recommendation"),
    }