"""
MCP tools for AI vulnerability analysis.
"""

from ai.analysis import (
    analyze_vulnerability,
    analyze_vulnerabilities
)


def run_ai_analysis(scanner_result):
    """
    Analyze one scanner vulnerability.

    Args:
        scanner_result (dict):
            One standardized scanner finding.

    Returns:
        dict:
            Structured AI vulnerability analysis.
    """

    return analyze_vulnerability(scanner_result)


def analyze_scan(findings):
    """
    Analyze multiple scanner vulnerabilities.

    This is the main interface for backend/MCP integration.

    Args:
        findings (list):
            List of standardized scanner findings.

    Returns:
        list:
            Structured AI analysis results.
    """

    return analyze_vulnerabilities(findings)