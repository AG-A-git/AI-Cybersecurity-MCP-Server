from ai.models import VulnerabilityInput
from ai.llm import analyze_vulnerability


scanner_result = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


vulnerability = VulnerabilityInput(
    **scanner_result
)


result = analyze_vulnerability(
    vulnerability
)


required_fields = [
    "file",
    "line",
    "vulnerability",
    "severity",
    "confidence",
    "risk_score",
    "risk_level",
    "explanation",
    "recommendation"
]


print("\n===== OUTPUT VALIDATION =====")

for field in required_fields:

    if field in result:
        print(f"{field}: OK")
    else:
        print(f"{field}: MISSING")


print("\n===== FINAL AI OUTPUT =====")
print(result)