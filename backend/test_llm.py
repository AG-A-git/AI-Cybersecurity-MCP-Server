from ai.llm import OllamaClient

client = OllamaClient()

prompt = """
Explain what SQL Injection is in two simple sentences.
"""

response = client.generate(prompt)

print("\nAI Response:\n")
print(response)