from .input import validate_vulnerability
from .risk_score import calculate_risk
from .mapping import get_mapping
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

    # 1. Validate scanner input
    finding = validate_vulnerability(vulnerability)

    # 2. Convert validated input to dictionary
    scanner_data = finding.model_dump()

    # 3. Build structured AI prompt
    prompt = build_structured_analysis_prompt(
        scanner_data
    )

    # 4. Call Ollama
    client = OllamaClient()

    raw_response = client.generate(prompt)

    ai_result = parse_ai_response(raw_response)

    # 5. Validate AI response
    ai_result = parse_ai_response(raw_response)

    # 6. Get vulnerability name
    vulnerability_name = finding.vulnerability

    # 7. Get OWASP and CWE
    mapping = get_mapping(vulnerability_name)

    # 8. Calculate risk score
    risk_score = calculate_risk(
    finding.severity,
    finding.confidence,
    finding.vulnerability
)

    # 9. Return final structured result
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
        "recommendation": ai_result.recommendation
    }