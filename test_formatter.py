from ai.utils import format_ai_response


result = format_ai_response(
    severity="Critical",
    risk_score=97,
    owasp="A03:2021 Injection",
    cwe="CWE-89",
    explanation="SQL Injection allows attackers to manipulate database queries.",
    recommendation="Use parameterized queries and prepared statements."
)


print("\n==============================")
print("FORMATTED AI RESPONSE")
print("==============================")


print(result)