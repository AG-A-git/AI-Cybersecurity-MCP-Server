from ai.prompts import build_structured_analysis_prompt


finding = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


prompt = build_structured_analysis_prompt(finding)

print(prompt)