"""
MCP tools for AI vulnerability analysis.
"""

from ai.llm import analyze_vulnerability
from ai.utils import format_ai_response


def run_ai_analysis(scanner_result):
    """
    Run complete AI vulnerability analysis.

    Args:
        scanner_result (dict):
            Vulnerability information from the scanner.

    Returns:
        dict:
            Formatted AI vulnerability analysis.
    """

    # Run the AI analysis pipeline
    analysis = analyze_vulnerability(scanner_result)

    # Format the result into the standard response
    formatted_response = format_ai_response(
        severity=analysis["severity"],
        risk_score=analysis["risk_score"],
        owasp=analysis["owasp"],
        cwe=analysis["cwe"],
        explanation=analysis["explanation"],
        recommendation=analysis["recommendation"]
    )

    return formatted_response