from .explanation import ExplanationGenerator
from .recommendation import RecommendationGenerator
from .risk_score import calculate_risk
from .mapping import get_mapping


def analyze_vulnerability(vulnerability):

    # Severity
    severity_map = {
        "SQL Injection": "Critical",
        "XSS": "High",
        "Hardcoded Credentials": "High"
    }

    severity = severity_map.get(
        vulnerability,
        "Medium"
    )

    # Risk score
    risk_score = calculate_risk(severity)

    # OWASP and CWE
    mapping = get_mapping(vulnerability)

    # AI explanation
    explanation_generator = ExplanationGenerator()

    explanation = explanation_generator.generate_explanation(
        vulnerability
    )

    # AI recommendation
    recommendation_generator = RecommendationGenerator()

    finding = {
        "type": vulnerability,
        "file": "example.py",
        "line": 10,
        "code": "Example vulnerable code"
    }

    recommendation = recommendation_generator.generate_recommendation(
        finding
    )

    return {
        "vulnerability": vulnerability,
        "severity": severity,
        "risk_score": risk_score,
        "owasp": mapping["owasp"],
        "cwe": mapping["cwe"],
        "explanation": explanation["explanation"],
        "recommendation": recommendation["recommendation"]
    }


if __name__ == "__main__":

    vulnerability = "XSS"

    result = analyze_vulnerability(vulnerability)

    print("\n==============================")
    print("AI VULNERABILITY ANALYSIS")
    print("==============================")

    print("\nVulnerability:")
    print(result["vulnerability"])

    print("\nSeverity:")
    print(result["severity"])

    print("\nRisk Score:")
    print(result["risk_score"])

    print("\nOWASP:")
    print(result["owasp"])

    print("\nCWE:")
    print(result["cwe"])

    print("\nExplanation:")
    print(result["explanation"])

    print("\nRecommendation:")
    print(result["recommendation"])