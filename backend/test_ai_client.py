from services.ai_client import analyze_vulnerability


finding = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


result = analyze_vulnerability(finding)

print("AI RESULT:")
print(result)