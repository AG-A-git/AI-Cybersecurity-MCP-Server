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
    Analyze standardized scanner findings using the AI analysis layer.

    The AI layer enriches findings but must not remove the original
    scanner information.

    Args:
        findings: List of normalized scanner findings.

    Returns:
        List of findings enriched with AI analysis.

    Raises:
        ValueError: If the input or AI response violates the contract.
        Exception: If the AI analysis layer fails.
    """

    if not isinstance(findings, list):
        raise ValueError("AI input must be a list of findings")

    results = []

    logger.info(
        "AI integration started | findings=%s",
        len(findings)
    )

    for index, finding in enumerate(findings):

        if not isinstance(finding, dict):
            raise ValueError(
                f"AI input finding at index {index} must be a dictionary"
            )

        try:
            analysis = analyze_vulnerability(finding)

            if not isinstance(analysis, dict):
                raise ValueError(
                    f"AI response at index {index} must be a dictionary"
                )

            combined_result = {
                **finding,
                **analysis
            }

            # Preserve the core scanner contract.
            for field in (
                "file",
                "line",
                "vulnerability",
                "severity",
                "confidence",
                "code"
            ):
                if field not in combined_result:
                    raise ValueError(
                        f"AI response removed required finding field: {field}"
                    )

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