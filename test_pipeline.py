from ai.llm import analyze_vulnerability


scanner_result = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


result = analyze_vulnerability(scanner_result)


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