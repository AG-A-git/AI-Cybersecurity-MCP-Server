from .llm import OllamaClient
from .prompts import get_prompt


class ExplanationGenerator:

    def __init__(self):
        self.client = OllamaClient()

    def generate_explanation(self, vulnerability):

        prompt = get_prompt(vulnerability)

        response = self.client.generate(prompt)

        return {
            "vulnerability": vulnerability,
            "explanation": response
        }


if __name__ == "__main__":

    generator = ExplanationGenerator()

    result = generator.generate_explanation(
        "SQL Injection"
    )

    print("\nAI Explanation:")
    print(result)