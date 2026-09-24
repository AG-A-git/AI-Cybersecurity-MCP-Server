from .input import validate_vulnerability
from .risk_score import (
    calculate_risk,
    classify_risk
)
from .mapping import get_mapping
from .response import parse_ai_response
from .llm import OllamaClient
from .prompts import (
    build_ai_input,
    build_structured_analysis_prompt
)


# ======================================================
# Analyze Multiple Findings
# ======================================================

def analyze_findings(findings):
    """
    Analyze multiple scanner findings.

    Args:
        findings: List of scanner vulnerability dictionaries.

    Returns:
        List of structured AI analysis results.
    """

    results = []

    for finding in findings:

        result = analyze_finding(
            finding
        )

        results.append(
            result
        )

    return results


# ======================================================
# Analyze One Finding
# ======================================================

def analyze_finding(
    vulnerability,
    client=None
):
    """
    Central orchestrator for analyzing one scanner finding.

    Args:
        vulnerability:
            Scanner vulnerability finding.

        client:
            Optional Ollama client, primarily useful for testing.

    Returns:
        Structured security analysis result.
    """

    # --------------------------------------------------
    # 1. Validate scanner input
    # --------------------------------------------------

    finding = validate_vulnerability(
        vulnerability
    )

    # --------------------------------------------------
    # 2. Convert validated finding to dictionary
    # --------------------------------------------------

    scanner_data = finding.model_dump()

    # --------------------------------------------------
    # 3. Build focused AI input
    # --------------------------------------------------

    ai_input = build_ai_input(
        scanner_data
    )

    # --------------------------------------------------
    # 4. Get deterministic vulnerability mapping
    # --------------------------------------------------

    vulnerability_name = finding.vulnerability

    mapping = get_mapping(
        vulnerability_name
    )

    # --------------------------------------------------
    # 5. Calculate deterministic risk
    # --------------------------------------------------

    risk_score = calculate_risk(
        finding.severity,
        finding.confidence,
        finding.vulnerability
    )

    # --------------------------------------------------
    # 5.1 Classify deterministic risk level
    # --------------------------------------------------

    risk_level = classify_risk(
        risk_score
    )

    # --------------------------------------------------
    # 6. Build base result
    # --------------------------------------------------

    result = {
        "file": finding.file,
        "line": finding.line,
        "vulnerability": vulnerability_name,
        "severity": finding.severity,
        "confidence": finding.confidence,

        # Deterministic risk information
        "risk_score": risk_score,
        "risk_level": risk_level,

        # Deterministic vulnerability mapping
        "owasp": mapping["owasp"],
        "cwe": mapping["cwe"],

        # AI lifecycle status
        "ai_status": "pending",

        # AI-generated information
        "explanation": None,
        "impact": None,
        "recommendation": None
    }

    # --------------------------------------------------
    # 7. Build structured AI prompt
    # --------------------------------------------------

    # AI is responsible only for:
    # - explanation
    # - impact
    # - recommendation
    #
    # Risk score, risk level, OWASP, and CWE remain
    # deterministic project outputs.

    try:

        prompt = build_structured_analysis_prompt(
            ai_input
        )

    except Exception:

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis could not be started."
        )

        return result

    # --------------------------------------------------
    # 8. Create AI client
    # --------------------------------------------------

    if client is None:

        client = OllamaClient()

    # --------------------------------------------------
    # 9. Mark AI analysis as running
    # --------------------------------------------------

    result["ai_status"] = "analyzing"

    # --------------------------------------------------
    # 10. Call Ollama with one controlled retry
    # --------------------------------------------------

    try:

        try:

            raw_response = client.generate(
                prompt
            )

        except (
            TimeoutError,
            RuntimeError
        ):

            # One controlled retry only
            raw_response = client.generate(
                prompt
            )

    except TimeoutError:

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis service unavailable."
        )

        return result

    except RuntimeError:

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis service unavailable."
        )

        return result

    except Exception:

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis service unavailable."
        )

        return result

    # --------------------------------------------------
    # 11. Validate AI response
    # --------------------------------------------------

    try:

        ai_result = parse_ai_response(
            raw_response
        )

    except Exception:

        result["ai_status"] = "failed"

        result["recommendation"] = (
            "AI analysis response was invalid."
        )

        return result

    # --------------------------------------------------
    # 12. Mark AI analysis successful
    # --------------------------------------------------

    result["ai_status"] = "completed"

    result["explanation"] = (
        ai_result.explanation
    )

    result["impact"] = (
        ai_result.impact
    )

    result["recommendation"] = (
        ai_result.recommendation
    )

    # IMPORTANT:
    # Do not allow AI output to modify:
    #
    # - risk_score
    # - risk_level
    # - owasp
    # - cwe

    return result


# ======================================================
# Backward-Compatible Alias
# ======================================================

def analyze_vulnerability(
    vulnerability
):
    """
    Backward-compatible wrapper for the previous
    function name.
    """

    return analyze_finding(
        vulnerability
    )