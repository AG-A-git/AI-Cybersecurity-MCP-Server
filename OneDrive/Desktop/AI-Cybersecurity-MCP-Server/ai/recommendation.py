from ai.llm import OllamaClient
from ai.prompts import RECOMMENDATION_MAP


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

        prompt = template.format(details=details)

        return self.client.generate(prompt)