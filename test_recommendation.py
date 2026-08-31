from ai.recommendation import RecommendationGenerator

finding = {
    "type": "SQL Injection",
    "file": "login.py",
    "line": 42,
    "code": "query = \"SELECT * FROM users WHERE username='\" + username + \"'\""
}

generator = RecommendationGenerator()

result = generator.generate_recommendation(finding)

print(result)