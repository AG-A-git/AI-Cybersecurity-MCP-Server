from .input import validate_vulnerability
from .risk_score import calculate_risk
from .vulnerability_mapping import get_vulnerability_mapping
from .response import parse_ai_response
from .llm import OllamaClient
from .prompts import build_structured_analysis_prompt


def analyze_vulnerabilities(findings):
    """
    Analyze multiple scanner findings.

    Args:
        findings: List of scanner vulnerability dictionaries.

    Returns:
        List of structured AI analysis results.
    """

    results = []

    for finding in findings:
        result = analyze_vulnerability(finding)
        results.append(result)

    return results


def analyze_vulnerability(vulnerability):
    """
    Analyze one scanner vulnerability finding.

    Flow:

        Scanner Finding
              ↓
        Input Validation
              ↓
        Structured Prompt
              ↓
        Ollama / Llama 3
              ↓
        JSON Parsing
              ↓
        AI Response Validation
              ↓
        OWASP/CWE Mapping
              ↓
        Deterministic Risk Score
              ↓
        Final Result
    """

    # --------------------------------------------------
    # 1. Validate scanner input
    # --------------------------------------------------

    finding = validate_vulnerability(vulnerability)

    # --------------------------------------------------
    # 2. Convert validated input to dictionary
    # --------------------------------------------------

    scanner_data = finding.model_dump()

    # --------------------------------------------------
    # 3. Build structured AI prompt
    # --------------------------------------------------

    prompt = build_structured_analysis_prompt(
        scanner_data
    )

    # --------------------------------------------------
    # 4. Call Ollama
    # --------------------------------------------------

    client = OllamaClient()

    raw_response = client.generate(prompt)

    # --------------------------------------------------
    # 5. Parse and validate AI response
    # --------------------------------------------------

    ai_result = parse_ai_response(raw_response)

    # --------------------------------------------------
    # 6. Get vulnerability name
    # --------------------------------------------------

    vulnerability_name = finding.vulnerability

    # --------------------------------------------------
    # 7. Get centralized OWASP/CWE mapping
    # --------------------------------------------------

    mapping = get_vulnerability_mapping(vulnerability_name)

    if mapping is None:
        mapping = {
            "owasp": "Unknown",
            "cwe": "Unknown"
            }

    # --------------------------------------------------
    # 8. Calculate deterministic risk score
    # --------------------------------------------------

    risk_score = calculate_risk(
        finding.severity,
        finding.confidence
    )

    # --------------------------------------------------
    # 9. Return final structured result
    # --------------------------------------------------

    return {
        "file": finding.file,
        "line": finding.line,
        "vulnerability": vulnerability_name,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "risk_score": risk_score,
        "owasp": mapping["owasp"],
        "cwe": mapping["cwe"],
        "explanation": ai_result.explanation,
        "impact": ai_result.impact,
        "recommendation": ai_result.recommendation,
        "secure_practice": ai_result.secure_practice
    }