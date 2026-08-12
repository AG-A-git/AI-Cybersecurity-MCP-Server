from ai.input import validate_vulnerability


finding = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


result = validate_vulnerability(finding)

print("Validation successful!")
print(result)