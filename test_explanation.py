from ai.explanation import ExplanationGenerator

finding = {
    "type": "SQL Injection",
    "file": "login.py",
    "line": 42,
    "code": "query = \"SELECT * FROM users WHERE username='\" + username + \"'\""
}

generator = ExplanationGenerator()

result = generator.generate_explanation(finding)

print(result)