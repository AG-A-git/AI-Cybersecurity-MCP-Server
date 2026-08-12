from ai.analysis import analyze_vulnerability


finding = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


result = analyze_vulnerability(finding)


print("\n==============================")
print("SCANNER → AI ANALYSIS")
print("==============================")


for key, value in result.items():
    print(f"\n{key}:")
    print(value)