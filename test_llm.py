from ai.llm import OllamaClient

client = OllamaClient()

prompt = "Explain SQL Injection in simple words."

response = client.generate(prompt)

print(response)