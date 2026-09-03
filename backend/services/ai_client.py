import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.analysis import analyze_vulnerability


def analyze_vulnerabilities(findings):
    """
    Analyze all scanner findings using the AI analysis layer.

    Args:
        findings: List of standardized scanner findings.

    Returns:
        List of findings enriched with AI analysis.
    """

    results = []

    for finding in findings:
        analysis = analyze_vulnerability(finding)

        combined_result = {
            **finding,
            **analysis
        }

        results.append(combined_result)

    return results