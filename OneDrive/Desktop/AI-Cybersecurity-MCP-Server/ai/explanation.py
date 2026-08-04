from ai.llm import OllamaClient
from ai.prompts import PROMPT_MAP


class ExplanationGenerator:
    def __init__(self):
        self.client = OllamaClient()

    def generate_explanation(self, finding):
        """
        finding should be a dictionary like:
        {
            "type": "SQL Injection",
            "file": "login.py",
            "line": 42,
            "code": "query = ..."
        }
        """

        vulnerability = finding.get("type")

        prompt_template = PROMPT_MAP.get(vulnerability)

        if not prompt_template:
            return f"No prompt available for: {vulnerability}"

        details = f"""
File: {finding.get("file")}
Line: {finding.get("line")}

Code:
{finding.get("code")}
"""

        prompt = prompt_template.format(details=details)

        return self.client.generate(prompt)