from .prompts import RECOMMENDATION_MAP
from .llm import OllamaClient


class RecommendationGenerator:

    def __init__(self):
        self.client = OllamaClient()

    def generate_recommendation(self, finding):

        vulnerability = finding.get("type")

        template = RECOMMENDATION_MAP.get(vulnerability)

        if not template:
            return f"No recommendation prompt found for {vulnerability}"

        details = f"""
File: {finding.get("file")}
Line: {finding.get("line")}

Code:
{finding.get("code")}
"""

        prompt = template.format(
            details=details
        )

        response = self.client.generate(prompt)

        return {
            "vulnerability": vulnerability,
            "recommendation": response
        }


if __name__ == "__main__":

    generator = RecommendationGenerator()

    finding = {
        "type": "SQL Injection",
        "file": "login.py",
        "line": 25,
        "code": "query = 'SELECT * FROM users WHERE id=' + user_id"
    }

    result = generator.generate_recommendation(finding)

    print("\n==============================")
    print("SECURITY RECOMMENDATION")
    print("==============================")

    print("\nVulnerability:")
    print(result["vulnerability"])

    print("\nRecommendation:")
    print(result["recommendation"])