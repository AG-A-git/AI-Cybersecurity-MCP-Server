
from ai.recommendation import RecommendationGenerator


def main():
    finding = {
        "type": "SQL Injection",
        "file": "login.py",
        "line": 42,
        "code": "query = \"SELECT * FROM users WHERE username='\" + username + \"'\"",
    }

    generator = RecommendationGenerator()
    result = generator.generate_recommendation(finding)
    print(result)


if __name__ == "__main__":
    main()
