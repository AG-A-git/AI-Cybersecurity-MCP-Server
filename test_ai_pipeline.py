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

print("\n===== AI ANALYSIS =====")
print(result)