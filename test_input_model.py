from ai.models import VulnerabilityInput


scanner_result = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


vulnerability = VulnerabilityInput(**scanner_result)

print("Input model created successfully:")
print(vulnerability)