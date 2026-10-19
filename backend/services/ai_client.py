
import sys
from pathlib import Path

from logging_config import get_logger

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.analysis import analyze_vulnerability
from ai.risk_score import calculate_risk
from ai.vulnerability_mapping import get_vulnerability_mapping

logger = get_logger(__name__)

SCANNER_FIELDS = (
    "file",
    "line",
    "vulnerability",
    "severity",
    "confidence",
    "code",
)


def fallback_finding(finding):
    """Preserve scanner evidence when AI enrichment is unavailable."""
    confidence = finding.get("confidence")
    if confidence is None:
        confidence = 0

    result = dict(finding)
    result["risk_score"] = calculate_risk(
        finding["severity"],
        confidence,
    )

    mapping = get_vulnerability_mapping(
        finding["vulnerability"]
    )

    result["owasp"] = mapping["owasp"] if mapping else None
    result["cwe"] = mapping["cwe"] if mapping else None

    # Do not invent AI-generated analysis.
    result["explanation"] = None
    result["impact"] = None
    result["recommendation"] = None

    return result


def analyze_vulnerabilities(findings):
    """
    Enrich scanner findings with AI when available.

    A failure for one finding must not discard scanner evidence or
    prevent other findings from being processed.
    """
    if not isinstance(findings, list):
        raise ValueError("AI input must be a list of findings")

    results = []
    logger.info("AI integration started | findings=%s", len(findings))

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ValueError(
                f"AI input finding at index {index} must be a dictionary"
            )

        # Scanner contract fields must already be present.
        for field in SCANNER_FIELDS:
            if field not in finding:
                raise ValueError(
                    f"Scanner finding is missing required field: {field}"
                )

        try:
            analysis = analyze_vulnerability(finding)

            if not isinstance(analysis, dict):
                raise ValueError(
                    f"AI response at index {index} must be a dictionary"
                )

            # Scanner values always take precedence over AI values.
            combined = {**analysis, **finding}

            for field in SCANNER_FIELDS:
                if field not in combined:
                    raise ValueError(
                        f"AI response removed required finding field: {field}"
                    )

            results.append(combined)

        except Exception:
            logger.exception(
                "AI enrichment unavailable; using deterministic fallback "
                "| finding_index=%s | file=%s",
                index,
                finding.get("file"),
            )
            results.append(fallback_finding(finding))

    logger.info(
        "AI integration finished | findings=%s",
        len(results),
    )
    return results
