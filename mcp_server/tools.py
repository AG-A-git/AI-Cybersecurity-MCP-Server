"""
MCP tools for AI vulnerability analysis.
"""

from ai.input import VulnerabilityInput
from ai.analysis import analyze_finding
from ai.batch import analyze_findings


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

    # analyze_finding expects the standardized finding
    # as a mapping/dictionary.
    return analyze_finding(finding.model_dump())


# ======================================================
# Analyze Multiple Vulnerabilities
# ======================================================

def analyze_scan(findings):
    """
    Analyze multiple scanner vulnerabilities.

    Uses the batch AI analysis pipeline so that one failed
    AI analysis does not stop the remaining findings.

    Args:
        findings (list):
            List of scanner vulnerability dictionaries.

    Returns:
        dict:
            Batch security analysis result.
    """

    return analyze_findings(findings)