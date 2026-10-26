
import requests

from .input import validate_vulnerability
from ._location_safeguard import remove_unverified_code_locations
from .risk_score import calculate_risk, classify_risk
from .mapping import get_mapping
from .response import parse_ai_response
from .llm import OllamaClient
from .prompts import (
    build_ai_input,
    build_structured_analysis_prompt,
)


# ======================================================
# Analyze Multiple Findings
# ======================================================

def analyze_findings(findings):
    """
    Analyze multiple scanner findings.

    Returns a list of structured AI analysis results.
    """
    results = []

    for finding in findings:
        result = analyze_finding(finding)
        results.append(result)

    return results


# ======================================================
# Analyze One Finding
# ======================================================

def analyze_finding(vulnerability, client=None):
    """
    Analyze one scanner finding.

    Scanner metadata, deterministic risk, and vulnerability
    mappings remain authoritative outside the AI client.
    """

    # 1. Validate scanner input
    finding = validate_vulnerability(vulnerability)

    # 2. Convert validated finding to a dictionary
    scanner_data = finding.model_dump()

    # 3. Build focused AI input
    ai_input = build_ai_input(scanner_data)

    # 4. Determine vulnerability mapping
    vulnerability_name = finding.vulnerability
    mapping = get_mapping(vulnerability_name)

    # 5. Calculate deterministic risk
    risk_score = calculate_risk(
        finding.severity,
        finding.confidence,
        finding.vulnerability,
    )

    # 6. Classify deterministic risk
    risk_level = classify_risk(risk_score)

    # 7. Build the base response
    result = {
        "file": finding.file,
        "line": finding.line,
        "code": finding.code,
        "vulnerability": vulnerability_name,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "owasp": mapping["owasp"],
        "cwe": mapping["cwe"],
        "ai_status": "pending",
        "explanation": None,
        "impact": None,
        "recommendation": None,
    }

    # 8. Build the structured prompt
    try:
        prompt = build_structured_analysis_prompt(ai_input)
    except Exception:
        result["ai_status"] = "failed"
        result["recommendation"] = (
            "AI analysis could not be started."
        )
        return result

    # 9. Create the AI client
    if client is None:
        client = OllamaClient()

    result["ai_status"] = "analyzing"

    # 10. Generate a response with one controlled retry
    try:
        try:
            raw_response = client.generate(prompt)

        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            TimeoutError,
            RuntimeError,
        ):
            # One retry for transient request/service failures.
            raw_response = client.generate(prompt)

    except Exception:
        result["ai_status"] = "failed"
        result["recommendation"] = (
            "AI analysis service unavailable."
        )
        return result

    # 11. Validate the AI response
    try:
        ai_result = parse_ai_response(raw_response)
    except Exception:
        result["ai_status"] = "failed"
        result["recommendation"] = (
            "AI analysis response was invalid."
        )
        return result

    # 12. Mark the analysis as successful
    result["ai_status"] = "completed"

    result["explanation"] = remove_unverified_code_locations(
        ai_result.explanation,
        finding.file,
        finding.line,
    )

    result["impact"] = remove_unverified_code_locations(
        ai_result.impact,
        finding.file,
        finding.line,
    )

    result["recommendation"] = remove_unverified_code_locations(
        ai_result.recommendation,
        finding.file,
        finding.line,
    )

    # AI output cannot override scanner metadata,
    # deterministic risk values, or vulnerability mappings.
    return result

# Backward-compatible aliases

def analyze_vulnerability(vulnerability):
    """Analyze one finding using the current analysis pipeline."""
    return analyze_finding(vulnerability)


def analyze_vulnerabilities(findings):
    """Analyze multiple findings using the current analysis pipeline."""
    return analyze_findings(findings)
