from ai.prompts import PROMPT_MAP
from ai.llm import OllamaClient

client = OllamaClient()

details = """
File: login.py
Line: 42
Code:
query = "SELECT * FROM users WHERE username='" + username + "'"
"""

prompt = PROMPT_MAP["SQL Injection"].format(details=details)

response = client.generate(prompt)

print(response)