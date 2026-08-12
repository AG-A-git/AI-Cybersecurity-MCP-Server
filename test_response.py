from ai.response import parse_ai_response


response = """
{
    "explanation": "The code is vulnerable to SQL injection.",
    "impact": "An attacker may manipulate the SQL query.",
    "recommendation": "Use parameterized queries.",
    "secure_practice": "Always use prepared statements."
}
"""


result = parse_ai_response(response)

print("\nVALIDATION SUCCESS")
print("==================")

print("Explanation:", result.explanation)
print("Impact:", result.impact)
print("Recommendation:", result.recommendation)
print("Secure Practice:", result.secure_practice)