import sys
from pathlib import Path

from logging_config import get_logger


# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from ai.analysis import analyze_vulnerability


logger = get_logger(__name__)


def analyze_vulnerabilities(findings):
    """
    Analyze all scanner findings using the AI analysis layer.

    This module acts as the backend-to-AI integration boundary.

    Args:
        findings: List of standardized scanner findings.

    Returns:
        List of findings enriched with AI analysis.

    Raises:
        Exception: Propagates AI failures to the scan service.
    """

    results = []

    logger.info(
        "AI integration started | findings=%s",
        len(findings)
    )

    for index, finding in enumerate(findings):

        try:

            analysis = analyze_vulnerability(finding)

            combined_result = {
                **finding,
                **analysis
            }

            results.append(combined_result)

        except Exception:

            logger.exception(
                "AI analysis failed | finding_index=%s",
                index
            )

            raise

    logger.info(
        "AI integration completed | findings=%s",
        len(results)
    )

    return results