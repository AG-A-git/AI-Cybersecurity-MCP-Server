from ai.prompts import build_structured_analysis_prompt
from ai.llm import OllamaClient


finding = {
    "file": "login.py",
    "line": 22,
    "vulnerability": "SQL Injection",
    "severity": "Critical",
    "confidence": 95,
    "code": "cursor.execute(query)"
}


prompt = build_structured_analysis_prompt(finding)

client = OllamaClient()

response = client.generate(prompt)

print("\n==============================")
print("STRUCTURED AI RESPONSE")
print("==============================")

print(response)