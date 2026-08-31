from ai.prompts import build_prompt


scanner_result = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


prompt = build_prompt(scanner_result)


print("\n==============================")
print("GENERATED AI PROMPT")
print("==============================")

print(prompt)