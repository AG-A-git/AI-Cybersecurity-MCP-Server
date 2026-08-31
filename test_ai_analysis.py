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


vulnerability = VulnerabilityInput(**scanner_result)

result = analyze_vulnerability(vulnerability)

print("\n===== AI ANALYSIS =====")
print(result)