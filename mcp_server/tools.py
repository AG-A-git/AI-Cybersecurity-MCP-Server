"""
MCP tools for AI vulnerability analysis.
"""

from ai.input import VulnerabilityInput
from ai.llm import analyze_vulnerability


# ======================================================
# Analyze One Vulnerability
# ======================================================

def run_ai_analysis(scanner_result):
    """
    Analyze one standardized scanner vulnerability.

    Args:
        scanner_result (dict):
            Scanner vulnerability finding.

    Returns:
        dict:
            Complete security analysis.
    """

    finding = VulnerabilityInput(
        file=scanner_result["file"],
        line=scanner_result["line"],
        vulnerability=scanner_result["vulnerability"],
        severity=scanner_result["severity"],
        confidence=scanner_result["confidence"],
        code=scanner_result["code"]
    )

    return analyze_vulnerability(finding)


# ======================================================
# Analyze Multiple Vulnerabilities
# ======================================================

def analyze_scan(findings):
    """
    Analyze multiple scanner vulnerabilities.

    Args:
        findings (list):
            List of scanner vulnerability dictionaries.

    Returns:
        list:
            List of security analysis results.
    """

    results = []

    for scanner_result in findings:

        result = run_ai_analysis(
            scanner_result
        )

        results.append(result)

    return results